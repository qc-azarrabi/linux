// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025 Andes Technology Corporation
 * Copyright (C) 2026 SiFive, Inc.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/mailbox/riscv-rpmi-message.h>
#include <linux/mailbox_client.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <asm/sbi.h>
#include <asm/smp.h>
#include "optee_conduit.h"
#include "optee_smc.h"

struct mpxy_tee_context {
	struct device *dev;
	struct mbox_chan **chan;
	struct mbox_client client;
	u32 max_msg_data_size;
};

static struct mpxy_tee_context *context;

/*
 * RPMI TEE Service Group Definitions
 * These values must match the RPMI TEE Service Group specification.
 */

/** RPMI TEE ServiceGroup Service IDs */
enum rpmi_tee_service_id {
	RPMI_TEE_SRV_ENABLE_NOTIFICATION = 0x01,
	RPMI_TEE_SRV_PROBE_FEATURES = 0x02,
	RPMI_TEE_SRV_MEM_PARCEL_CREATE = 0x09,
	RPMI_TEE_SRV_MEM_PARCEL_ACCEPT = 0x0A,
	RPMI_TEE_SRV_MEM_PARCEL_RELEASE = 0x0B,
	RPMI_TEE_SRV_MEM_PARCEL_RECLAIM = 0x0C,
	RPMI_TEE_SRV_TEE_CALL = 0x13,
	RPMI_TEE_SRV_MAX_COUNT,
};

/** RPMI TEE feature IDs for TEE_PROBE_FEATURES (must match OpenSBI) */
enum rpmi_tee_feature_id {
	RPMI_TEE_FEAT_MEMORY_DONATE = 1,
	RPMI_TEE_FEAT_MEMORY_LEND = 2,
	RPMI_TEE_FEAT_MEMORY_SHARE = 3,
	RPMI_TEE_FEAT_SIGNAL_BUS = 4,
	RPMI_TEE_FEAT_MULTISEGMENT_OPS = 5,
	RPMI_TEE_FEAT_SYSINFO_FORMAT = 6,
};

/** TEE_PROBE_FEATURES request / response (must match OpenSBI) */
struct rpmi_tee_probe_features_req {
	__le32 feature_id;
};

struct rpmi_tee_probe_features_resp {
	__le32 status;
	__le32 value;
};

/*
 * Memory parcel wire encodings (RPMI spec section 4.16, Tables 198-207).
 * These MUST byte-match the OpenSBI definitions in
 * <sbi_utils/mailbox/rpmi_msgprot.h>. All fields are little-endian uint32
 * words; block-list addresses are expressed in units of 4kB pages.
 */

/* Memory access encoding (Table 199) */
#define RPMI_TEE_PARCEL_ACCESS_R	(1U << 29)
#define RPMI_TEE_PARCEL_ACCESS_W	(1U << 30)
#define RPMI_TEE_PARCEL_ACCESS_X	(1U << 31)

/* MEM_PARCEL_CREATE FLAGS (Table 200) */
#define RPMI_TEE_PARCEL_CREATE_FLAG_MULTI_SEGMENT	(1U << 31)
#define RPMI_TEE_PARCEL_CREATE_FLAG_OWNER_XFER		(1U << 30)

/* Block list encoding (Table 198): addresses in 4kB page units */
#define RPMI_TEE_PARCEL_LABEL_LEN	16

/* MEM_PARCEL_CREATE request (Table 200): header + receiver/access/block arrays */
struct rpmi_tee_mem_parcel_create_req {
	__le32 creator_id;
	__le32 creator_access;
	__le32 receiver_cnt;
	__le32 flags;
	__le32 nonce;
	__le32 block_cnt;
	u8 label[RPMI_TEE_PARCEL_LABEL_LEN];
	__le32 data[];
};

struct rpmi_tee_mem_parcel_create_resp {
	__le32 status;
	__le32 mem_parcel_id;
};

/* MEM_PARCEL_ACCEPT request (Table 202): header + other_id/other_access arrays */
struct rpmi_tee_mem_parcel_accept_req {
	__le32 acceptor_id;
	__le32 access;
	__le32 mem_parcel_id;
	__le32 nonce;
	__le32 creator_id;
	__le32 creator_access;
	__le32 flags;
	__le32 address_high;
	__le32 address_low;
	__le32 max_pages;
	__le32 other_cnt;
	__le32 data[];
};

/* MEM_PARCEL_ACCEPT response (Table 203): header + block_high/block_low arrays */
struct rpmi_tee_mem_parcel_accept_resp {
	__le32 status;
	__le32 flags;
	__le32 page_cnt;
	__le32 block_cnt;
	__le32 data[];
};

/* MEM_PARCEL_RELEASE request (Table 204) */
struct rpmi_tee_mem_parcel_release_req {
	__le32 mem_parcel_id;
	__le32 flags;
	__le32 endpoint_cnt;
	__le32 endpoint_id[];
};

struct rpmi_tee_mem_parcel_release_resp {
	__le32 status;
};

/* MEM_PARCEL_RECLAIM request (Table 206) */
struct rpmi_tee_mem_parcel_reclaim_req {
	__le32 mem_parcel_id;
};

struct rpmi_tee_mem_parcel_reclaim_resp {
	__le32 status;
	__le32 flags;
};

/** TEE Implementation IDs */
enum rpmi_tee_impl_id {
	RPMI_TEE_IMPL_ID_OPTEE = 0x00000000,
	/* 0x00000001 - 0x7FFFFFFF: Reserved for future use */
	/* 0x80000000 - 0xFFFFFFFF: Implementation specific */
};

/** OP-TEE specific communication parameters */
#define RPMI_TEE_OPTEE_COMM_REQ_REGS	8	/* a0-a7 */
#define RPMI_TEE_OPTEE_COMM_RESP_REGS	4	/* a0-a3 */

/*
 * Fixed TEE endpoint identities and the well-known "OP-TEE communicate"
 * service UUID for TEE_CALL (RPMI spec section 4.16). These MUST byte-match the
 * OpenSBI definitions in <sbi_utils/mailbox/rpmi_msgprot.h>.
 *
 * UUID: 5be1b1a0-7e11-4e7a-9b10-0010c0ffee00
 */
#define RPMI_TEE_ENDPOINT_REE		0
#define RPMI_TEE_ENDPOINT_OPTEE	1

static const u8 rpmi_tee_optee_service_uuid[16] = {
	0x5b, 0xe1, 0xb1, 0xa0, 0x7e, 0x11, 0x4e, 0x7a,
	0x9b, 0x10, 0x00, 0x10, 0xc0, 0xff, 0xee, 0x00
};

/*
 * RPMI XLEN-sized type for TEE Service Group
 *
 * Per RPMI TEE spec, registers are XLEN-sized little-endian values:
 *   Request size  = COMM_REQ_REGS  × (XLEN / 8)
 *   Response size = COMM_RESP_REGS × (XLEN / 8) + 4 (status)
 *
 * For RV64: Request = 64 bytes, Response = 36 bytes
 * For RV32: Request = 32 bytes, Response = 20 bytes
 */
#if __riscv_xlen == 64
typedef __le64 rpmi_xlen_t;
#define cpu_to_rpmi_xlen(x)	cpu_to_le64(x)
#define rpmi_xlen_to_cpu(x)	le64_to_cpu(x)
#else
typedef __le32 rpmi_xlen_t;
#define cpu_to_rpmi_xlen(x)	cpu_to_le32(x)
#define rpmi_xlen_to_cpu(x)	le32_to_cpu(x)
#endif

/**
 * TEE_CALL request for OP-TEE (RPMI spec section 4.16, Table 218)
 *
 * Fixed identity (SENDER=REE, TARGET=OP-TEE) + well-known service UUID, then
 * SERVICE_DATA carrying the SMC-style a0-a7 register block.
 * For RV64: header 28 + 8 * 8 = 92 bytes
 * For RV32: header 28 + 8 * 4 = 60 bytes
 *
 * __packed so the u8[16] UUID does not force padding before service_data_len.
 */
struct rpmi_tee_optee_req {
	__le32 sender_id;
	__le32 target_id;
	u8 service[16];
	__le32 service_data_len;
	/* SERVICE_DATA: register block a0-a7 */
	rpmi_xlen_t a0;
	rpmi_xlen_t a1;
	rpmi_xlen_t a2;
	rpmi_xlen_t a3;
	rpmi_xlen_t a4;
	rpmi_xlen_t a5;
	rpmi_xlen_t a6;
	rpmi_xlen_t a7;
} __packed;

/**
 * TEE_CALL response for OP-TEE (RPMI spec section 4.16, Table 219)
 *
 * Response format (packed, per RPMI spec):
 *   Word 0:      STATUS (s32)
 *   Word 1:      SERVICE_RSP_LEN (u32)
 *   Words 2+:    SERVICE_RSP = a0-a3 (XLEN-sized little-endian)
 *
 * For RV64: 4 + 4 + 4*8 = 40 bytes
 * For RV32: 4 + 4 + 4*4 = 24 bytes
 *
 * a0 is already stripped by the OpenSBI OP-TEE dispatcher; the four registers
 * here are the OP-TEE return values a0-a3.
 *
 * Must use __packed to prevent padding between the header words and the regs.
 */
struct rpmi_tee_optee_resp {
	__le32 status;
	__le32 service_rsp_len;
	rpmi_xlen_t a0;
	rpmi_xlen_t a1;
	rpmi_xlen_t a2;
	rpmi_xlen_t a3;
} __packed;

static int hartid_to_cpuid(unsigned long hartid, unsigned int nr_cpus)
{
	for (int i = 0; i < nr_cpus; i++) {
		if (cpuid_to_hartid_map(i) == hartid)
			return i;
	}
	return -ENOENT;
}

static inline int __mpxy_mbox_send_message(struct rpmi_mbox_message *msg)
{
	int cpu, ret;

	cpu = get_cpu();
	ret = rpmi_mbox_send_message(context->chan[cpu], msg);
	put_cpu();

	return ret;
}

/**
 * optee_riscv_sbi_mpxy() - Invoke OP-TEE via RPMI TEE_CALL (0x13)
 *
 * This function sends an SMC-style request to OP-TEE using the RPMI
 * TEE Service Group (0x0010). The TEE_CALL request wraps the 8 XLEN-sized
 * registers (a0-a7) as SERVICE_DATA behind a fixed REE->OP-TEE identity and
 * the well-known OP-TEE service UUID; the response carries STATUS +
 * SERVICE_RSP_LEN + 4 XLEN-sized registers (a0-a3).
 *
 * Request size:  28 + 8 * sizeof(unsigned long) = 92 bytes (RV64)
 * Response size:  8 + 4 * sizeof(unsigned long) = 40 bytes (RV64)
 */
static void optee_riscv_sbi_mpxy(unsigned long a0, unsigned long a1,
				 unsigned long a2, unsigned long a3,
				 unsigned long a4, unsigned long a5,
				 unsigned long a6, unsigned long a7,
				 struct optee_conduit_res *res)
{
	struct rpmi_tee_optee_req tx = {
		.sender_id = cpu_to_le32(RPMI_TEE_ENDPOINT_REE),
		.target_id = cpu_to_le32(RPMI_TEE_ENDPOINT_OPTEE),
		.service_data_len =
			cpu_to_le32(RPMI_TEE_OPTEE_COMM_REQ_REGS *
				    sizeof(rpmi_xlen_t)),
		.a0 = cpu_to_rpmi_xlen(a0), .a1 = cpu_to_rpmi_xlen(a1),
		.a2 = cpu_to_rpmi_xlen(a2), .a3 = cpu_to_rpmi_xlen(a3),
		.a4 = cpu_to_rpmi_xlen(a4), .a5 = cpu_to_rpmi_xlen(a5),
		.a6 = cpu_to_rpmi_xlen(a6), .a7 = cpu_to_rpmi_xlen(a7)
	};
	struct rpmi_tee_optee_resp rx = {0};
	struct rpmi_mbox_message msg = {0};
	int ret;

	memcpy(tx.service, rpmi_tee_optee_service_uuid, sizeof(tx.service));

	rpmi_mbox_init_send_with_response(&msg, RPMI_TEE_SRV_TEE_CALL,
					  &tx, sizeof(tx), &rx, sizeof(rx));
	ret = __mpxy_mbox_send_message(&msg);
	if (ret) {
		pr_err_ratelimited(
			"%s: TEE MPXY messaging failed, errno: %d\n",
			__func__, ret);
		res->a0 = OPTEE_SMC_RETURN_ENOTAVAIL;
		return;
	}

	/* Check RPMI status from firmware */
	if (le32_to_cpu(rx.status) != 0) {
		pr_err_ratelimited(
			"%s: TEE RPMI error, status: %d\n",
			__func__, le32_to_cpu(rx.status));
		res->a0 = OPTEE_SMC_RETURN_ENOTAVAIL;
		return;
	}

	/* Copy OP-TEE return values (convert from little-endian XLEN) */
	res->a0 = rpmi_xlen_to_cpu(rx.a0);
	res->a1 = rpmi_xlen_to_cpu(rx.a1);
	res->a2 = rpmi_xlen_to_cpu(rx.a2);
	res->a3 = rpmi_xlen_to_cpu(rx.a3);
}

/*
 * Log the framework-answered TEE services (TEE_PROBE_FEATURES and
 * TEE_ENABLE_NOTIFICATION) at probe time. This proves the request/response
 * marshalling end-to-end independently of any OP-TEE domain switch.
 */
static void riscv_mpxy_tee_probe_features(void)
{
	static const char * const feat_name[] = {
		[RPMI_TEE_FEAT_MEMORY_DONATE]	= "MEMORY_DONATE",
		[RPMI_TEE_FEAT_MEMORY_LEND]	= "MEMORY_LEND",
		[RPMI_TEE_FEAT_MEMORY_SHARE]	= "MEMORY_SHARE",
		[RPMI_TEE_FEAT_SIGNAL_BUS]	= "SIGNAL_BUS",
		[RPMI_TEE_FEAT_MULTISEGMENT_OPS] = "MULTISEGMENT_OPS",
		[RPMI_TEE_FEAT_SYSINFO_FORMAT]	= "SYSINFO_FORMAT",
	};
	struct rpmi_mbox_message msg;
	u32 id;
	int ret;

	for (id = RPMI_TEE_FEAT_MEMORY_DONATE;
	     id <= RPMI_TEE_FEAT_SYSINFO_FORMAT; id++) {
		struct rpmi_tee_probe_features_req tx = {
			.feature_id = cpu_to_le32(id),
		};
		struct rpmi_tee_probe_features_resp rx = {0};

		rpmi_mbox_init_send_with_response(&msg, RPMI_TEE_SRV_PROBE_FEATURES,
						  &tx, sizeof(tx), &rx, sizeof(rx));
		ret = __mpxy_mbox_send_message(&msg);
		if (ret) {
			pr_info("PROBE_FEATURES[%u %s] send failed: %d\n",
				id, feat_name[id], ret);
			continue;
		}
		pr_info("PROBE_FEATURES[%u %s] status=%d value=%u\n",
			id, feat_name[id], le32_to_cpu(rx.status),
			le32_to_cpu(rx.value));
	}

	/* TEE_ENABLE_NOTIFICATION: no events in this group -> expect NOTSUPP */
	{
		struct rpmi_tee_probe_features_resp rx = {0};

		rpmi_mbox_init_send_with_response(&msg,
						  RPMI_TEE_SRV_ENABLE_NOTIFICATION,
						  NULL, 0, &rx, sizeof(rx));
		ret = __mpxy_mbox_send_message(&msg);
		if (ret)
			pr_info("ENABLE_NOTIFICATION send failed: %d\n",
				ret);
		else
			pr_info("ENABLE_NOTIFICATION status=%d (expect NOTSUPP=-2)\n",
				le32_to_cpu(rx.status));
	}
}

/* Send MEM_PARCEL_CREATE for a single block; return status, set *out_id. */
static int parcel_do_create(u32 nonce, u32 creator_access, u32 recv_access,
			    u32 flags, u64 page, u32 npages, u32 *out_id)
{
	u8 buf[sizeof(struct rpmi_tee_mem_parcel_create_req) + 4 * sizeof(__le32)];
	struct rpmi_tee_mem_parcel_create_req *req = (void *)buf;
	struct rpmi_tee_mem_parcel_create_resp rx = {0};
	struct rpmi_mbox_message msg;
	int ret;

	memset(buf, 0, sizeof(buf));
	req->creator_id = cpu_to_le32(RPMI_TEE_ENDPOINT_REE);
	req->creator_access = cpu_to_le32(creator_access);
	req->receiver_cnt = cpu_to_le32(1);
	req->flags = cpu_to_le32(flags);
	req->nonce = cpu_to_le32(nonce);
	req->block_cnt = cpu_to_le32(1);
	/* data[]: receiver_id[1], access[1], block_high[1], block_low[1] */
	req->data[0] = cpu_to_le32(RPMI_TEE_ENDPOINT_OPTEE);
	req->data[1] = cpu_to_le32(recv_access);
	req->data[2] = cpu_to_le32((u32)(page >> 20));
	req->data[3] = cpu_to_le32((u32)(((page & 0xFFFFF) << 12) | (npages - 1)));

	rpmi_mbox_init_send_with_response(&msg, RPMI_TEE_SRV_MEM_PARCEL_CREATE,
					  req, sizeof(buf), &rx, sizeof(rx));
	ret = __mpxy_mbox_send_message(&msg);
	if (ret)
		return ret;
	if (out_id)
		*out_id = le32_to_cpu(rx.mem_parcel_id);
	return le32_to_cpu(rx.status);
}

/* Send MEM_PARCEL_ACCEPT (single receiver); return status, report block list. */
static int parcel_do_accept(u32 id, u32 nonce, u32 creator_access, u32 access,
			    u32 flags, u32 max_pages, u32 *out_bc, u32 *out_pc,
			    __le32 *out_high, __le32 *out_low)
{
	u8 rbuf[sizeof(struct rpmi_tee_mem_parcel_accept_resp) + 2 * sizeof(__le32)];
	struct rpmi_tee_mem_parcel_accept_resp *rx = (void *)rbuf;
	struct rpmi_tee_mem_parcel_accept_req tx = {0};
	struct rpmi_mbox_message msg;
	int ret;
	u32 bc;

	memset(rbuf, 0, sizeof(rbuf));
	tx.acceptor_id = cpu_to_le32(RPMI_TEE_ENDPOINT_OPTEE);
	tx.access = cpu_to_le32(access);
	tx.mem_parcel_id = cpu_to_le32(id);
	tx.nonce = cpu_to_le32(nonce);
	tx.creator_id = cpu_to_le32(RPMI_TEE_ENDPOINT_REE);
	tx.creator_access = cpu_to_le32(creator_access);
	tx.flags = cpu_to_le32(flags);
	tx.max_pages = cpu_to_le32(max_pages);

	rpmi_mbox_init_send_with_response(&msg, RPMI_TEE_SRV_MEM_PARCEL_ACCEPT,
					  &tx, sizeof(tx), rx, sizeof(rbuf));
	ret = __mpxy_mbox_send_message(&msg);
	if (ret)
		return ret;

	bc = le32_to_cpu(rx->block_cnt);
	if (out_bc)
		*out_bc = bc;
	if (out_pc)
		*out_pc = le32_to_cpu(rx->page_cnt);
	if (bc >= 1) {
		/* data[]: block_high[bc] then block_low[bc] */
		if (out_high)
			*out_high = rx->data[0];
		if (out_low)
			*out_low = rx->data[bc];
	}
	return le32_to_cpu(rx->status);
}

/* Send MEM_PARCEL_RELEASE for a single endpoint; return status. */
static int parcel_do_release(u32 id, u32 endpoint)
{
	u8 buf[sizeof(struct rpmi_tee_mem_parcel_release_req) + sizeof(__le32)];
	struct rpmi_tee_mem_parcel_release_req *req = (void *)buf;
	struct rpmi_tee_mem_parcel_release_resp rx = {0};
	struct rpmi_mbox_message msg;
	int ret;

	memset(buf, 0, sizeof(buf));
	req->mem_parcel_id = cpu_to_le32(id);
	req->endpoint_cnt = cpu_to_le32(1);
	req->endpoint_id[0] = cpu_to_le32(endpoint);

	rpmi_mbox_init_send_with_response(&msg, RPMI_TEE_SRV_MEM_PARCEL_RELEASE,
					  req, sizeof(buf), &rx, sizeof(rx));
	ret = __mpxy_mbox_send_message(&msg);
	if (ret)
		return ret;
	return le32_to_cpu(rx.status);
}

/* Send MEM_PARCEL_RECLAIM; return status. */
static int parcel_do_reclaim(u32 id)
{
	struct rpmi_tee_mem_parcel_reclaim_req tx = {
		.mem_parcel_id = cpu_to_le32(id),
	};
	struct rpmi_tee_mem_parcel_reclaim_resp rx = {0};
	struct rpmi_mbox_message msg;
	int ret;

	rpmi_mbox_init_send_with_response(&msg, RPMI_TEE_SRV_MEM_PARCEL_RECLAIM,
					  &tx, sizeof(tx), &rx, sizeof(rx));
	ret = __mpxy_mbox_send_message(&msg);
	if (ret)
		return ret;
	return le32_to_cpu(rx.status);
}

/*
 * Exercise the framework-answered memory parcel lifecycle at probe time. A
 * single two-page block is described from REE-owned memory and driven through
 * the positive path (CREATE -> ACCEPT -> RELEASE -> RECLAIM) plus the negative
 * cases the firmware state machine must reject. Results are logged with a
 * "PARCEL" prefix; no OP-TEE domain switch is involved.
 */
static void riscv_mpxy_tee_parcel_selftest(void)
{
	const u32 rw = RPMI_TEE_PARCEL_ACCESS_R | RPMI_TEE_PARCEL_ACCESS_W;
	const u32 npages = 2;
	unsigned long va;
	u64 page, exp_high, exp_low;
	u32 id, bc, pc;
	__le32 bh, bl;
	int st;

	va = __get_free_pages(GFP_KERNEL, 1); /* 2 contiguous pages */
	if (!va) {
		pr_info("PARCEL selftest: page allocation failed\n");
		return;
	}
	page = (u64)virt_to_phys((void *)va) >> 12;
	exp_high = page >> 20;
	exp_low = ((page & 0xFFFFF) << 12) | (npages - 1);

	/* Positive: share R|W through the full lifecycle. */
	st = parcel_do_create(0x1234, rw, rw, 0, page, npages, &id);
	pr_info("PARCEL create status=%d id=0x%x (expect 0)\n", st, id);
	if (st == 0) {
		bc = pc = 0;
		bh = bl = 0;
		st = parcel_do_accept(id, 0x1234, rw, rw, 0, npages,
				      &bc, &pc, &bh, &bl);
		pr_info("PARCEL accept status=%d block_cnt=%u page_cnt=%u match=%d (expect 0)\n",
			st, bc, pc,
			(bc == 1 && pc == npages &&
			 le32_to_cpu(bh) == (u32)exp_high &&
			 le32_to_cpu(bl) == (u32)exp_low));
		st = parcel_do_release(id, RPMI_TEE_ENDPOINT_OPTEE);
		pr_info("PARCEL release status=%d (expect 0)\n", st);
		st = parcel_do_reclaim(id);
		pr_info("PARCEL reclaim status=%d (expect 0)\n", st);
	}

	/* Negative: ACCEPT with a mismatched nonce -> INVALID_PARAM. */
	st = parcel_do_create(0x2000, rw, rw, 0, page, npages, &id);
	if (st == 0) {
		st = parcel_do_accept(id, 0x2001, rw, rw, 0, npages,
				      NULL, NULL, NULL, NULL);
		pr_info("PARCEL neg bad-nonce accept status=%d (expect -3)\n", st);
		parcel_do_reclaim(id);
	}

	/* Negative: acceptor capacity below parcel size -> INVALID_PARAM. */
	st = parcel_do_create(0x3000, rw, rw, 0, page, npages, &id);
	if (st == 0) {
		st = parcel_do_accept(id, 0x3000, rw, rw, 0, npages - 1,
				      NULL, NULL, NULL, NULL);
		pr_info("PARCEL neg small-maxpages accept status=%d (expect -3)\n",
			st);
		parcel_do_reclaim(id);
	}

	/* Negative: RECLAIM while a receiver still holds the parcel -> DENIED. */
	st = parcel_do_create(0x4000, rw, rw, 0, page, npages, &id);
	if (st == 0) {
		parcel_do_accept(id, 0x4000, rw, rw, 0, npages,
				 NULL, NULL, NULL, NULL);
		st = parcel_do_reclaim(id);
		pr_info("PARCEL neg reclaim-before-release status=%d (expect -4)\n",
			st);
		parcel_do_release(id, RPMI_TEE_ENDPOINT_OPTEE);
		parcel_do_reclaim(id);
	}

	/*
	 * Owner-transfer (donate). The creator keeps no access but the
	 * receiver still gets R|W (creator_access == 0 no longer caps the
	 * receiver's grant on a donate), so ACCEPT succeeds and destroys the
	 * handle; a later RECLAIM of the same id then fails lookup with
	 * INVALID_PARAM.
	 */
	st = parcel_do_create(0x5000, 0, rw,
			      RPMI_TEE_PARCEL_CREATE_FLAG_OWNER_XFER,
			      page, npages, &id);
	pr_info("PARCEL donate create status=%d id=0x%x (expect 0)\n", st, id);
	if (st == 0) {
		st = parcel_do_accept(id, 0x5000, 0, rw, 0, npages,
				      NULL, NULL, NULL, NULL);
		pr_info("PARCEL donate accept status=%d (expect 0)\n", st);
		st = parcel_do_reclaim(id);
		pr_info("PARCEL donate reclaim status=%d (expect -3, destroyed)\n",
			st);
	}

	free_pages(va, 1);
	pr_info("PARCEL selftest done\n");
}

/*
 * OP-TEE fast-call ABI id for parcel consumption. Mirrors the OP-TEE core
 * definition OPTEE_ABI_CONSUME_PARCEL = FAST_CALL | (TRUSTED_OS << 24) | func:
 *   0x80000000 | (50 << 24) | 0x100 = 0xB2000100.
 */
#define OPTEE_ABI_CONSUME_PARCEL	0xB2000100U

/*
 * End-to-end parcel consumption: create a parcel over a REE page, ask OP-TEE
 * (via the TEE_CALL fast path) to accept it, map it, and write a known pattern
 * into the shared memory, then read the page back in the REE and confirm the
 * TEE actually touched it. OP-TEE releases the parcel inside the call, so the
 * REE only needs to reclaim the handle afterwards.
 */
static void riscv_mpxy_tee_parcel_consume_selftest(void)
{
	const u32 rw = RPMI_TEE_PARCEL_ACCESS_R | RPMI_TEE_PARCEL_ACCESS_W;
	const u32 nonce = 0x6000;
	const u32 pattern = 0xdeadbeefU;
	struct optee_conduit_res res = {0};
	unsigned long va;
	u64 page;
	u32 readback;
	u32 id;
	int st;

	va = __get_free_pages(GFP_KERNEL, 0); /* 1 page */
	if (!va) {
		pr_info("PARCEL consume: page allocation failed\n");
		return;
	}
	memset((void *)va, 0, PAGE_SIZE);
	page = (u64)virt_to_phys((void *)va) >> 12;

	st = parcel_do_create(nonce, rw, rw, 0, page, 1, &id);
	pr_info("PARCEL consume create status=%d id=0x%x (expect 0)\n", st, id);
	if (st == 0) {
		/*
		 * TEE_CALL forwards the full a0-a7 block (the TEE MPXY channel
		 * uses a PAGE_SIZE message buffer), so a1-a4 would work too; the
		 * four 32-bit consume arguments are packed into a1/a2 by choice
		 * to keep the request compact:
		 *   a1 = parcel_id      | (nonce   << 32)
		 *   a2 = creator_access | (pattern << 32)
		 */
		optee_riscv_sbi_mpxy(OPTEE_ABI_CONSUME_PARCEL,
				     (u64)id | ((u64)nonce << 32),
				     (u64)rw | ((u64)pattern << 32),
				     0, 0, 0, 0, 0, &res);
		readback = *(volatile u32 *)va;
		pr_info("PARCEL consume tee status=%lu echo=0x%llx (expect 0)\n",
			res.a0, (u64)res.a1);
		pr_info("PARCEL consume readback=0x%x pattern=0x%x match=%d\n",
			readback, pattern, readback == pattern);
		st = parcel_do_reclaim(id);
		pr_info("PARCEL consume reclaim status=%d (expect 0)\n", st);
	}

	free_pages(va, 0);
	pr_info("PARCEL consume selftest done\n");
}

static int riscv_mpxy_mbox_probe(struct device *dev)
{
        struct rpmi_mbox_message msg;
        struct device_node *np, *cpu_np;
        u64 hartid, size;
        unsigned int nr_cpus;
        u32 channel_id;
        int ret, cpuid;

        /* Allocate RPXY TEE context */
        context = devm_kzalloc(dev, sizeof(*context), GFP_KERNEL);
        if (!context)
                return -ENOMEM;
        context->dev = dev;

        /* Setup mailbox client */
        context->client.dev             = context->dev;
        context->client.rx_callback     = NULL;
        context->client.tx_block        = false;
        context->client.knows_txdone    = true;
        context->client.tx_tout         = 0;

        /* Calculate how many harts we have */
        nr_cpus = 0;
        for (cpuid = 0; cpuid < NR_CPUS; cpuid++) {
                unsigned long hartid = cpuid_to_hartid_map(cpuid);

                if (hartid == INVALID_HARTID ||
                    hartid >= (unsigned long) NR_CPUS)
                        break;
                nr_cpus++;
        }
        /* Request mailbox channels per hart */
        context->chan = devm_kcalloc(dev, nr_cpus, sizeof(*context->chan),
                                     GFP_KERNEL);
        /* DT example:
         * cpu0: cpu@0 {
         *     reg = <0x0>;  // hartid = 0
         *     ...
         *     rpmi_tee_0: rpmi-tee {
         *         compatible = "riscv,rpmi-mpxy-tee";
         *         riscv,sbi-mpxy-channel-id = <0x0>;
         *         opensbi-domain-instance = <&tdomain>;
         *     };
         *     rpmi_reqfwd_0: rpmi-reqfwd {
         *         compatible = "riscv,sbi-mpxy-reqfwd";
         *         riscv,sbi-mpxy-channel-id = <0x10>;
         *     };
         * };
         */
        for_each_compatible_node(np, NULL, "riscv,rpmi-mpxy-tee") {
                ret = of_property_read_u32(np, "riscv,sbi-mpxy-channel-id", &channel_id);
                if (ret) {
                        panic("Missing riscv,sbi-mpxy-channel-id property in node %pOF\n", np);
                }

                cpu_np = of_get_parent(np);
                if (!cpu_np) {
                        panic("Failed to get parent CPU node for %pOF\n", np);
                }

                ret = of_property_read_reg(cpu_np, 0, &hartid, &size);
                of_node_put(cpu_np);
                if (ret) {
                        panic("Failed to get hartid from parent CPU node for %pOF\n", np);
                }

                cpuid = hartid_to_cpuid(hartid, nr_cpus);
                if (cpuid < 0) {
                        panic("Invalid hartid %llu in node %pOF\n", hartid, np);
                }

                context->chan[cpuid] = mbox_request_channel(&context->client,
                                                            channel_id);
                if (IS_ERR(context->chan[cpuid])) {
                        ret = PTR_ERR(context->chan[cpuid]);
                        dev_err_probe(dev, ret, "Failed to get mbox channel\n");
                        goto fail_free_channel;
                }

                pr_info("Probed RPMI OP-TEE channel %u (dedicated to hart%llu)\n",
                        channel_id, hartid);
        }

        /* Save the maximum message data size of mailbox channel */
        rpmi_mbox_init_get_attribute(&msg, RPMI_MBOX_ATTR_MAX_MSG_DATA_SIZE);
        ret = __mpxy_mbox_send_message(&msg);
        if (ret) {
                dev_err_probe(dev, ret, "Failed to get max msg data size\n");
                goto fail_free_channel;
        }
        context->max_msg_data_size = msg.attr.value;

        /* Log framework-answered TEE services (PROBE_FEATURES / notify) */
        riscv_mpxy_tee_probe_features();

        /* Exercise the framework-answered memory parcel lifecycle. */
        riscv_mpxy_tee_parcel_selftest();

        /* Exercise end-to-end OP-TEE-side parcel consumption. */
        riscv_mpxy_tee_parcel_consume_selftest();

        return 0;

fail_free_channel:
        for (cpuid = 0; cpuid < nr_cpus; cpuid++) {
                if (context->chan[cpuid])
                        mbox_free_channel(context->chan[cpuid]);
        }

        return ret;
}

optee_invoke_fn *arch_get_invoke_func(struct device *dev)
{
	const char *method;
	int ret;

	pr_info("probing for conduit method.\n");

	if (device_property_read_string(dev, "method", &method)) {
		pr_warn("missing \"method\" property\n");
		return ERR_PTR(-ENXIO);
	}

	if (!strcmp("mpxy", method)) {
		ret = riscv_mpxy_mbox_probe(dev);
		if (ret)
			return ERR_PTR(ret);

		return optee_riscv_sbi_mpxy;
	}

	pr_warn("invalid \"method\" property: %s\n", method);
	return ERR_PTR(-EINVAL);
}
