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
	RPMI_TEE_SRV_PROBE_SYSTEM = 0x03,
	RPMI_TEE_SRV_MEM_PARCEL_CREATE = 0x09,
	RPMI_TEE_SRV_MEM_PARCEL_ACCEPT = 0x0A,
	RPMI_TEE_SRV_MEM_PARCEL_RELEASE = 0x0B,
	RPMI_TEE_SRV_MEM_PARCEL_RECLAIM = 0x0C,
	RPMI_TEE_SRV_MEM_PARCEL_SEGMENT_SEND = 0x0D,
	RPMI_TEE_SRV_MEM_PARCEL_SEGMENT_RECEIVE = 0x0E,
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

/** TEE_PROBE_SYSTEM request / response (must match OpenSBI) */
#define RPMI_TEE_SYSINFO_FORMAT_NONE	0
#define RPMI_TEE_SYSINFO_FORMAT_CBOR	1

struct rpmi_tee_probe_system_req {
	__le32 reserved;
};

struct rpmi_tee_probe_system_resp {
	__le32 status;
	__le32 format;
	__le32 info_len;
	u8 data[];
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

/* ACCEPT response FLAGS: block list did not fit, pull remainder via RECEIVE */
#define RPMI_TEE_PARCEL_ACCEPT_RESP_FLAG_MULTI_SEGMENT	(1U << 31)

/* SEGMENT_SEND/RECEIVE (0x0D/0x0E): stream a block list too large for one msg */
#define RPMI_TEE_PARCEL_SEGMENT_FLAG_LAST	(1U << 31)
#define RPMI_TEE_PARCEL_SEGMENT_MAX_BLOCKS	4

/* SEGMENT_SEND request: header + block_high[block_cnt] block_low[block_cnt] */
struct rpmi_tee_mem_parcel_segment_send_req {
	__le32 mem_parcel_id;
	__le32 flags;
	__le32 block_cnt;
	__le32 data[];
};

struct rpmi_tee_mem_parcel_segment_send_resp {
	__le32 status;
};

/* SEGMENT_RECEIVE request: pull the next segment for an in-progress accept */
struct rpmi_tee_mem_parcel_segment_receive_req {
	__le32 acceptor_id;
	__le32 mem_parcel_id;
};

/* SEGMENT_RECEIVE response: header + block_high[block_cnt] block_low[block_cnt] */
struct rpmi_tee_mem_parcel_segment_receive_resp {
	__le32 status;
	__le32 flags;
	__le32 block_cnt;
	__le32 data[];
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

/*
 * Minimal CBOR reader for the fixed PROBE_SYSTEM system-info map. Only the
 * subset the OpenSBI encoder emits is decoded: a short definite-length map of
 * short text-string keys to unsigned integers. Advances *off; returns 0 on a
 * successfully decoded pair, negative on malformed input or overflow.
 */
static int cbor_read_uint(const u8 *buf, u32 len, u32 *off, u32 *out)
{
	u8 b;

	if (*off >= len)
		return -1;
	b = buf[(*off)++];
	if (b < 24) {
		*out = b;
	} else if (b == 0x18) {
		if (*off + 1 > len)
			return -1;
		*out = buf[(*off)++];
	} else if (b == 0x19) {
		if (*off + 2 > len)
			return -1;
		*out = ((u32)buf[*off] << 8) | buf[*off + 1];
		*off += 2;
	} else if (b == 0x1a) {
		if (*off + 4 > len)
			return -1;
		*out = ((u32)buf[*off] << 24) | ((u32)buf[*off + 1] << 16) |
		       ((u32)buf[*off + 2] << 8) | buf[*off + 3];
		*off += 4;
	} else {
		return -1;
	}
	return 0;
}

/*
 * TEE_PROBE_SYSTEM (0x03): request the CBOR system-info blob and print the
 * decoded parcel-manager capacities. Framework-answered; QEMU-testable.
 */
static void riscv_mpxy_tee_probe_system(void)
{
	struct rpmi_tee_probe_system_req tx = { .reserved = 0 };
	struct {
		struct rpmi_tee_probe_system_resp resp;
		u8 data[128];
	} rx = {0};
	struct rpmi_mbox_message msg;
	u32 off = 0, npairs, i, format, info_len;
	const u8 *blob = rx.resp.data;
	int ret;

	rpmi_mbox_init_send_with_response(&msg, RPMI_TEE_SRV_PROBE_SYSTEM,
					  &tx, sizeof(tx), &rx, sizeof(rx));
	ret = __mpxy_mbox_send_message(&msg);
	if (ret) {
		pr_info("PROBE_SYSTEM send failed: %d\n", ret);
		return;
	}

	format = le32_to_cpu(rx.resp.format);
	info_len = le32_to_cpu(rx.resp.info_len);
	pr_info("PROBE_SYSTEM status=%d format=%u info_len=%u (expect 0/1 CBOR)\n",
		le32_to_cpu(rx.resp.status), format, info_len);

	if (format != RPMI_TEE_SYSINFO_FORMAT_CBOR || info_len > sizeof(rx.data))
		return;

	/* Map header (major type 5). */
	if (off >= info_len || (blob[off] & 0xe0) != 0xa0) {
		pr_info("PROBE_SYSTEM CBOR: not a map\n");
		return;
	}
	npairs = blob[off++] & 0x1f;

	for (i = 0; i < npairs; i++) {
		u32 klen, kstart, val;
		char key[24];

		if (off >= info_len || (blob[off] & 0xe0) != 0x60)
			break;
		klen = blob[off++] & 0x1f;
		if (off + klen > info_len || klen >= sizeof(key))
			break;
		kstart = off;
		memcpy(key, &blob[kstart], klen);
		key[klen] = '\0';
		off += klen;
		if (cbor_read_uint(blob, info_len, &off, &val))
			break;
		pr_info("PROBE_SYSTEM cap %s=%u\n", key, val);
	}
	pr_info("PROBE_SYSTEM selftest done\n");
}

/* Send MEM_PARCEL_CREATE for a single 4kB-page block; return status + id. */
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
 * MEM_PARCEL_CREATE with the MULTI_SEGMENT flag and no initial block batch:
 * carries only the receiver metadata and leaves the parcel constructing. The
 * block list is streamed afterward via SEGMENT_SEND.
 */
static int parcel_do_create_multiseg(u32 nonce, u32 creator_access,
				     u32 recv_access, u32 *out_id)
{
	u8 buf[sizeof(struct rpmi_tee_mem_parcel_create_req) + 2 * sizeof(__le32)];
	struct rpmi_tee_mem_parcel_create_req *req = (void *)buf;
	struct rpmi_tee_mem_parcel_create_resp rx = {0};
	struct rpmi_mbox_message msg;
	int ret;

	memset(buf, 0, sizeof(buf));
	req->creator_id = cpu_to_le32(RPMI_TEE_ENDPOINT_REE);
	req->creator_access = cpu_to_le32(creator_access);
	req->receiver_cnt = cpu_to_le32(1);
	req->flags = cpu_to_le32(RPMI_TEE_PARCEL_CREATE_FLAG_MULTI_SEGMENT);
	req->nonce = cpu_to_le32(nonce);
	req->block_cnt = cpu_to_le32(0);
	/* data[]: receiver_id[1], access[1] (no blocks yet) */
	req->data[0] = cpu_to_le32(RPMI_TEE_ENDPOINT_OPTEE);
	req->data[1] = cpu_to_le32(recv_access);

	rpmi_mbox_init_send_with_response(&msg, RPMI_TEE_SRV_MEM_PARCEL_CREATE,
					  req, sizeof(buf), &rx, sizeof(rx));
	ret = __mpxy_mbox_send_message(&msg);
	if (ret)
		return ret;
	if (out_id)
		*out_id = le32_to_cpu(rx.mem_parcel_id);
	return le32_to_cpu(rx.status);
}

/*
 * SEGMENT_SEND: append a batch of one-page blocks (base_page .. base_page+n-1)
 * to the parcel under construction; set last on the final segment. The
 * server tracks segment ordering itself, so no client-supplied index is
 * sent. Returns status.
 */
static int parcel_do_segment_send(u32 id, bool last, u64 base_page, u32 n)
{
	u8 buf[sizeof(struct rpmi_tee_mem_parcel_segment_send_req) +
	       2 * RPMI_TEE_PARCEL_SEGMENT_MAX_BLOCKS * sizeof(__le32)];
	struct rpmi_tee_mem_parcel_segment_send_req *req = (void *)buf;
	struct rpmi_tee_mem_parcel_segment_send_resp rx = {0};
	struct rpmi_mbox_message msg;
	u32 i;
	int ret;

	memset(buf, 0, sizeof(buf));
	req->mem_parcel_id = cpu_to_le32(id);
	req->flags = cpu_to_le32(last ? RPMI_TEE_PARCEL_SEGMENT_FLAG_LAST : 0);
	req->block_cnt = cpu_to_le32(n);
	/* data[]: block_high[n] then block_low[n] */
	for (i = 0; i < n; i++) {
		u64 page = base_page + i;

		req->data[i] = cpu_to_le32((u32)(page >> 20));
		req->data[n + i] =
			cpu_to_le32((u32)(((page & 0xFFFFF) << 12) | 0));
	}

	rpmi_mbox_init_send_with_response(&msg,
					  RPMI_TEE_SRV_MEM_PARCEL_SEGMENT_SEND,
					  req,
					  sizeof(*req) + 2 * n * sizeof(__le32),
					  &rx, sizeof(rx));
	ret = __mpxy_mbox_send_message(&msg);
	if (ret)
		return ret;
	return le32_to_cpu(rx.status);
}

/*
 * SEGMENT_RECEIVE: pull up to RPMI_TEE_PARCEL_SEGMENT_MAX_BLOCKS blocks of the
 * next unreceived segment into out_high[]/out_low[]. The server tracks the
 * receive cursor itself; acceptor_id identifies the caller as the registered
 * receiver. Returns status; reports the count returned and whether this was
 * the final segment.
 */
static int parcel_do_segment_receive(u32 id, u32 acceptor_id, u32 *out_bc,
				     bool *out_last, __le32 *out_high,
				     __le32 *out_low)
{
	u8 rbuf[sizeof(struct rpmi_tee_mem_parcel_segment_receive_resp) +
		2 * RPMI_TEE_PARCEL_SEGMENT_MAX_BLOCKS * sizeof(__le32)];
	struct rpmi_tee_mem_parcel_segment_receive_resp *rx = (void *)rbuf;
	struct rpmi_tee_mem_parcel_segment_receive_req tx = {0};
	struct rpmi_mbox_message msg;
	u32 bc, i;
	int ret;

	memset(rbuf, 0, sizeof(rbuf));
	tx.acceptor_id = cpu_to_le32(acceptor_id);
	tx.mem_parcel_id = cpu_to_le32(id);

	rpmi_mbox_init_send_with_response(&msg,
					  RPMI_TEE_SRV_MEM_PARCEL_SEGMENT_RECEIVE,
					  &tx, sizeof(tx), rx, sizeof(rbuf));
	ret = __mpxy_mbox_send_message(&msg);
	if (ret)
		return ret;

	bc = le32_to_cpu(rx->block_cnt);
	if (out_bc)
		*out_bc = bc;
	if (out_last)
		*out_last = !!(le32_to_cpu(rx->flags) &
			       RPMI_TEE_PARCEL_SEGMENT_FLAG_LAST);
	/* data[]: block_high[bc] then block_low[bc] */
	for (i = 0; i < bc && i < RPMI_TEE_PARCEL_SEGMENT_MAX_BLOCKS; i++) {
		if (out_high)
			out_high[i] = rx->data[i];
		if (out_low)
			out_low[i] = rx->data[bc + i];
	}
	return le32_to_cpu(rx->status);
}

/*
 * Exercise the multi-segment block-list path. A block list larger than one
 * SEGMENT batch describes eight one-page blocks over a contiguous REE
 * allocation. The list is CREATED as multi-segment (metadata only), streamed in
 * with two SEGMENT_SEND batches, ACCEPTED (returning the full list), and then
 * pulled back one bounded segment at a time with SEGMENT_RECEIVE - which caps
 * each response at RPMI_TEE_PARCEL_SEGMENT_MAX_BLOCKS, so eight blocks require
 * multiple receives and the final segment carries the LAST flag. Every block is
 * verified against the known physical pages. Logged with a "PARCEL" prefix.
 */
static void riscv_mpxy_tee_parcel_multiseg_selftest(void)
{
	const u32 rw = RPMI_TEE_PARCEL_ACCESS_R | RPMI_TEE_PARCEL_ACCESS_W;
	const u32 nblocks = 8;		/* > SEGMENT_MAX_BLOCKS (=4) */
	const u32 nonce = 0x7000;
	/* ACCEPT response buffer large enough for the whole block list. */
	u8 rbuf[sizeof(struct rpmi_tee_mem_parcel_accept_resp) +
		2 * 8 * sizeof(__le32)];
	struct rpmi_tee_mem_parcel_accept_resp *arx = (void *)rbuf;
	struct rpmi_tee_mem_parcel_accept_req atx = {0};
	struct rpmi_mbox_message msg;
	__le32 rhigh[RPMI_TEE_PARCEL_SEGMENT_MAX_BLOCKS];
	__le32 rlow[RPMI_TEE_PARCEL_SEGMENT_MAX_BLOCKS];
	unsigned long va;
	u64 base_page;
	u32 id = 0, acc_bc, acc_flags, i, ok;
	u32 start, seg_count, recv_total;
	bool last = false;
	int st;

	va = __get_free_pages(GFP_KERNEL, 3);	/* 8 contiguous pages */
	if (!va) {
		pr_info("PARCEL multiseg: page allocation failed\n");
		return;
	}
	base_page = (u64)virt_to_phys((void *)va) >> 12;

	/* CREATE multi-segment (metadata only, no initial blocks). */
	st = parcel_do_create_multiseg(nonce, rw, rw, &id);
	pr_info("PARCEL multiseg create status=%d id=0x%x (expect 0)\n", st, id);
	if (st != 0)
		goto out;

	/* Stream the 8 blocks in two 4-block segments; LAST finalizes. */
	st = parcel_do_segment_send(id, false, base_page, 4);
	pr_info("PARCEL multiseg send seg0 status=%d (expect 0)\n", st);
	if (st != 0)
		goto out_reclaim;
	st = parcel_do_segment_send(id, true, base_page + 4, 4);
	pr_info("PARCEL multiseg send seg1(LAST) status=%d (expect 0)\n", st);
	if (st != 0)
		goto out_reclaim;

	/* ACCEPT: the whole list fits, so it returns all blocks in one response. */
	memset(rbuf, 0, sizeof(rbuf));
	atx.acceptor_id = cpu_to_le32(RPMI_TEE_ENDPOINT_OPTEE);
	atx.access = cpu_to_le32(rw);
	atx.mem_parcel_id = cpu_to_le32(id);
	atx.nonce = cpu_to_le32(nonce);
	atx.creator_id = cpu_to_le32(RPMI_TEE_ENDPOINT_REE);
	atx.creator_access = cpu_to_le32(rw);
	atx.max_pages = cpu_to_le32(nblocks);
	rpmi_mbox_init_send_with_response(&msg, RPMI_TEE_SRV_MEM_PARCEL_ACCEPT,
					  &atx, sizeof(atx), arx, sizeof(rbuf));
	st = __mpxy_mbox_send_message(&msg);
	if (st) {
		pr_info("PARCEL multiseg accept send failed: %d\n", st);
		goto out_reclaim;
	}
	st = le32_to_cpu(arx->status);
	acc_bc = le32_to_cpu(arx->block_cnt);
	acc_flags = le32_to_cpu(arx->flags);
	pr_info("PARCEL multiseg accept status=%d block_cnt=%u multiseg=%d (expect 0/8/0)\n",
		st, acc_bc,
		!!(acc_flags & RPMI_TEE_PARCEL_ACCEPT_RESP_FLAG_MULTI_SEGMENT));
	if (st != 0)
		goto out_release;

	/* Verify all blocks carried in the ACCEPT response. */
	ok = (acc_bc == nblocks) ? 1 : 0;
	for (i = 0; i < acc_bc && i < nblocks; i++) {
		u64 page = base_page + i;

		if (le32_to_cpu(arx->data[i]) != (u32)(page >> 20) ||
		    le32_to_cpu(arx->data[acc_bc + i]) !=
			    (u32)(((page & 0xFFFFF) << 12) | 0))
			ok = 0;
	}
	pr_info("PARCEL multiseg accept blocklist match=%d (expect 1)\n", ok);

	/*
	 * Receive-side segmentation: SEGMENT_RECEIVE caps each response at
	 * RPMI_TEE_PARCEL_SEGMENT_MAX_BLOCKS blocks, so pull the full list back
	 * one bounded segment at a time until the LAST flag is set, verifying
	 * every block. Eight blocks / four-per-segment => at least two segments.
	 */
	ok = 1;
	start = 0;
	seg_count = 0;
	recv_total = 0;
	do {
		u32 rbc = 0;

		st = parcel_do_segment_receive(id, RPMI_TEE_ENDPOINT_OPTEE,
					       &rbc, &last, rhigh, rlow);
		if (st != 0) {
			pr_info("PARCEL multiseg receive seg%u status=%d (expect 0)\n",
				seg_count, st);
			ok = 0;
			break;
		}
		if (rbc == 0 || rbc > RPMI_TEE_PARCEL_SEGMENT_MAX_BLOCKS)
			ok = 0;
		for (i = 0; i < rbc && i < RPMI_TEE_PARCEL_SEGMENT_MAX_BLOCKS; i++) {
			u64 page = base_page + start + i;

			if (le32_to_cpu(rhigh[i]) != (u32)(page >> 20) ||
			    le32_to_cpu(rlow[i]) !=
				    (u32)(((page & 0xFFFFF) << 12) | 0))
				ok = 0;
		}
		start += rbc;
		recv_total += rbc;
		seg_count++;
		pr_info("PARCEL multiseg receive seg%u block_cnt=%u last=%d\n",
			seg_count - 1, rbc, last);
	} while (!last && seg_count < 16);

	pr_info("PARCEL multiseg receive segments=%u blocks=%u match=%d (expect >=2/8/1)\n",
		seg_count, recv_total,
		(ok && recv_total == nblocks && last && seg_count >= 2));

out_release:
	parcel_do_release(id, RPMI_TEE_ENDPOINT_OPTEE);
out_reclaim:
	parcel_do_reclaim(id);
out:
	free_pages(va, 3);
	pr_info("PARCEL multiseg selftest done\n");
}

/*
 * Exercise the framework-answered memory parcel lifecycle: the positive share
 * round trip (create -> accept -> release -> reclaim), three negative cases
 * the firmware state machine must reject, and the donate/owner-transfer case.
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
	 * Negative: owner-transfer (donate). The creator keeps no access, so
	 * ACCEPT succeeds and destroys the handle; a later RECLAIM of the same
	 * id then fails lookup with INVALID_PARAM.
	 */
	st = parcel_do_create(0x5000, 0, 0,
			      RPMI_TEE_PARCEL_CREATE_FLAG_OWNER_XFER,
			      page, npages, &id);
	pr_info("PARCEL donate create status=%d id=0x%x (expect 0)\n", st, id);
	if (st == 0) {
		st = parcel_do_accept(id, 0x5000, 0, 0, 0, npages,
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

        /* Print the CBOR system-info capacities (PROBE_SYSTEM). */
        riscv_mpxy_tee_probe_system();

        /* Exercise the framework-answered memory parcel lifecycle. */
        riscv_mpxy_tee_parcel_selftest();

        /* Exercise end-to-end OP-TEE-side parcel consumption. */
        riscv_mpxy_tee_parcel_consume_selftest();

        /* Exercise the multi-segment block-list transfer path. */
        riscv_mpxy_tee_parcel_multiseg_selftest();

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
