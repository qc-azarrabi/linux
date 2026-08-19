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
