// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2025 The RISC-V OP-TEE contributors
 *
 * This file implements the ABI used when communicating with secure world
 * OP-TEE OS over the RPMI TEE service group (RPMI spec section 4.16).  It is
 * the RISC-V analog of ffa_abi.c: OP-TEE and Linux are peer endpoints of the
 * RPMI framework (OpenSBI), and shared memory follows the FF-A memory-donation
 * model through the RPMI memory parcel services.
 *
 * This file is divided into the following sections:
 * 1. Low level RPMI TEE service group transport over the SBI MPXY mailbox
 * 2. Feature discovery and notification handshake
 * 3. Driver initialization
 *
 * The remaining FF-A-equivalent sections (parcel id hash table, tee_param
 * marshalling, dynamic shared memory pool and the scheduled call into secure
 * world) are added on top of this transport layer.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/errno.h>
#include <linux/mailbox_client.h>
#include <linux/mailbox/riscv-rpmi-message.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/tee_core.h>
#include <linux/types.h>

#include <asm/smp.h>

#include "optee_private.h"
#include "optee_riscv.h"

/*
 * 1. Low level RPMI TEE service group transport over the SBI MPXY mailbox
 *
 * The RPMI TEE service group is reached through the SBI MPXY mailbox.  Each
 * hart owns a dedicated MPXY channel so that a call issued on a given hart is
 * serviced by the OP-TEE context bound to it; optee_riscv_send() therefore
 * selects the channel of the running hart.  All RPMI messages are exchanged
 * synchronously with rpmi_mbox_send_message().
 */

static int optee_riscv_send(struct optee *optee, struct rpmi_mbox_message *msg)
{
	int cpu, ret;

	cpu = get_cpu();
	if (cpu >= optee->riscv.nr_chan || !optee->riscv.chan[cpu]) {
		put_cpu();
		return -ENODEV;
	}
	ret = rpmi_mbox_send_message(optee->riscv.chan[cpu], msg);
	put_cpu();

	return ret;
}

/*
 * 2. Feature discovery and notification handshake
 *
 * TEE_PROBE_FEATURES (0x02) reports which framework features are available;
 * TEE_ENABLE_NOTIFICATION (0x01) subscribes to TEE service group events.  Both
 * are mandatory services (RPMI spec section 4.16), so probing them also
 * confirms that the framework speaks the TEE service group on this channel.
 */

static int optee_riscv_probe_feature(struct optee *optee, u32 feature_id,
				     u32 *value)
{
	struct rpmi_tee_probe_features_req tx = {
		.feature_id = cpu_to_le32(feature_id),
	};
	struct rpmi_tee_probe_features_resp rx = { };
	struct rpmi_mbox_message msg;
	int ret;

	rpmi_mbox_init_send_with_response(&msg, RPMI_TEE_SRV_PROBE_FEATURES,
					  &tx, sizeof(tx), &rx, sizeof(rx));
	ret = optee_riscv_send(optee, &msg);
	if (ret)
		return ret;
	if (rx.status)
		return rpmi_to_linux_error(le32_to_cpu(rx.status));

	if (value)
		*value = le32_to_cpu(rx.value);

	return 0;
}

static int optee_riscv_features(struct optee *optee)
{
	u32 share = RPMI_TEE_MEMORY_SHARE_NONE;
	int ret;

	/*
	 * Memory parcels carry normal-world shared memory to OP-TEE, so the
	 * framework must support sharing memory between the REE and a TEE.
	 */
	ret = optee_riscv_probe_feature(optee, RPMI_TEE_FEAT_MEMORY_SHARE,
					&share);
	if (ret) {
		pr_err("Failed to probe MEMORY_SHARE feature: %d\n", ret);
		return ret;
	}
	if (share != RPMI_TEE_MEMORY_SHARE_FULL) {
		pr_err("Framework cannot share memory between REE and TEE (%u)\n",
		       share);
		return -EOPNOTSUPP;
	}

	return 0;
}

static int optee_riscv_enable_notif(struct optee *optee)
{
	struct rpmi_tee_probe_features_resp rx = { };
	struct rpmi_mbox_message msg;
	int ret;

	rpmi_mbox_init_send_with_response(&msg, RPMI_TEE_SRV_ENABLE_NOTIFICATION,
					  NULL, 0, &rx, sizeof(rx));
	ret = optee_riscv_send(optee, &msg);
	if (ret)
		return ret;

	/*
	 * The TEE service group defines no notification events on this
	 * platform, so RPMI_ERR_NOTSUPP is expected and not fatal.
	 */
	if (rx.status && le32_to_cpu(rx.status) != (u32)RPMI_ERR_NOTSUPP)
		return rpmi_to_linux_error(le32_to_cpu(rx.status));

	return 0;
}

/*
 * 3. Driver initialization
 *
 * The RPMI TEE service group is described in the device tree as one
 * "riscv,rpmi-mpxy-tee" node per hart, each carrying a dedicated MPXY channel
 * id.  The driver requests one mailbox channel per hart and validates the
 * transport before building the OP-TEE device.
 */

static int optee_riscv_count_cpus(void)
{
	int nr_cpus = 0;
	int cpuid;

	for (cpuid = 0; cpuid < NR_CPUS; cpuid++) {
		unsigned long hartid = cpuid_to_hartid_map(cpuid);

		if (hartid == INVALID_HARTID || hartid >= (unsigned long)NR_CPUS)
			break;
		nr_cpus++;
	}

	return nr_cpus;
}

static int optee_riscv_hartid_to_cpuid(unsigned long hartid,
				       unsigned int nr_cpus)
{
	unsigned int cpuid;

	for (cpuid = 0; cpuid < nr_cpus; cpuid++) {
		if (cpuid_to_hartid_map(cpuid) == hartid)
			return cpuid;
	}

	return -ENOENT;
}

static int optee_riscv_request_channels(struct optee *optee)
{
	struct device *dev = optee->riscv.dev;
	struct device_node *np;
	int ret;

	for_each_compatible_node(np, NULL, "riscv,rpmi-mpxy-tee") {
		struct device_node *cpu_np;
		u64 hartid, size;
		u32 channel_id;
		int cpuid;

		ret = of_property_read_u32(np, "riscv,sbi-mpxy-channel-id",
					   &channel_id);
		if (ret) {
			dev_err(dev, "Missing channel id in %pOF\n", np);
			goto err_put_np;
		}

		cpu_np = of_get_parent(np);
		if (!cpu_np) {
			ret = -EINVAL;
			dev_err(dev, "Missing parent CPU node for %pOF\n", np);
			goto err_put_np;
		}
		ret = of_property_read_reg(cpu_np, 0, &hartid, &size);
		of_node_put(cpu_np);
		if (ret) {
			dev_err(dev, "Missing hartid for %pOF\n", np);
			goto err_put_np;
		}

		cpuid = optee_riscv_hartid_to_cpuid(hartid, optee->riscv.nr_chan);
		if (cpuid < 0) {
			ret = cpuid;
			dev_err(dev, "Invalid hartid %llu in %pOF\n", hartid, np);
			goto err_put_np;
		}

		optee->riscv.chan[cpuid] =
			mbox_request_channel(optee->riscv.client, channel_id);
		if (IS_ERR(optee->riscv.chan[cpuid])) {
			ret = PTR_ERR(optee->riscv.chan[cpuid]);
			optee->riscv.chan[cpuid] = NULL;
			dev_err(dev, "Failed to request channel %u: %d\n",
				channel_id, ret);
			goto err_put_np;
		}
	}

	return 0;

err_put_np:
	of_node_put(np);
	return ret;
}

static void optee_riscv_free_channels(struct optee *optee)
{
	unsigned int i;

	for (i = 0; i < optee->riscv.nr_chan; i++) {
		if (optee->riscv.chan[i])
			mbox_free_channel(optee->riscv.chan[i]);
	}
}

static int optee_riscv_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct rpmi_mbox_message msg;
	struct mbox_client *client;
	struct optee *optee;
	u32 servicegroup_id;
	int nr_cpus, ret;

	nr_cpus = optee_riscv_count_cpus();
	if (nr_cpus <= 0)
		return dev_err_probe(dev, -ENODEV, "No harts found\n");

	optee = kzalloc_obj(*optee);
	if (!optee)
		return -ENOMEM;

	client = devm_kzalloc(dev, sizeof(*client), GFP_KERNEL);
	if (!client) {
		ret = -ENOMEM;
		goto err_free_optee;
	}
	client->dev		= dev;
	client->rx_callback	= NULL;
	client->tx_block	= false;
	client->knows_txdone	= true;
	client->tx_tout		= 0;

	optee->riscv.dev = dev;
	optee->riscv.client = client;
	optee->riscv.nr_chan = nr_cpus;
	optee->riscv.chan = kcalloc(nr_cpus, sizeof(*optee->riscv.chan),
				    GFP_KERNEL);
	if (!optee->riscv.chan) {
		ret = -ENOMEM;
		goto err_free_optee;
	}

	ret = optee_riscv_request_channels(optee);
	if (ret)
		goto err_free_channels;

	/* Confirm the channel really speaks the TEE service group. */
	rpmi_mbox_init_get_attribute(&msg, RPMI_MBOX_ATTR_SERVICEGROUP_ID);
	ret = optee_riscv_send(optee, &msg);
	if (ret) {
		dev_err_probe(dev, ret, "Failed to get service group id\n");
		goto err_free_channels;
	}
	servicegroup_id = msg.attr.value;
	if (servicegroup_id != RPMI_SRVGRP_TEE) {
		ret = -ENODEV;
		dev_err_probe(dev, ret, "Not a TEE service group channel (0x%x)\n",
			      servicegroup_id);
		goto err_free_channels;
	}

	rpmi_mbox_init_get_attribute(&msg, RPMI_MBOX_ATTR_MAX_MSG_DATA_SIZE);
	ret = optee_riscv_send(optee, &msg);
	if (ret) {
		dev_err_probe(dev, ret, "Failed to get max msg data size\n");
		goto err_free_channels;
	}
	optee->riscv.max_msg_data_size = msg.attr.value;

	ret = optee_riscv_features(optee);
	if (ret) {
		dev_err_probe(dev, ret, "Missing required TEE features\n");
		goto err_free_channels;
	}

	ret = optee_riscv_enable_notif(optee);
	if (ret) {
		dev_err_probe(dev, ret, "Failed to enable notifications\n");
		goto err_free_channels;
	}

	platform_set_drvdata(pdev, optee);
	dev_info(dev, "initialized driver\n");

	return 0;

err_free_channels:
	optee_riscv_free_channels(optee);
	kfree(optee->riscv.chan);
err_free_optee:
	kfree(optee);
	return ret;
}

static void optee_riscv_remove(struct platform_device *pdev)
{
	struct optee *optee = platform_get_drvdata(pdev);

	optee_riscv_free_channels(optee);
	kfree(optee->riscv.chan);
	kfree(optee);
}

static const struct of_device_id optee_riscv_match[] = {
	{ .compatible = "riscv,rpmi-mpxy-tee" },
	{ }
};
MODULE_DEVICE_TABLE(of, optee_riscv_match);

static struct platform_driver optee_riscv_driver = {
	.driver = {
		.name = DRIVER_NAME "-riscv",
		.of_match_table = optee_riscv_match,
	},
	.probe = optee_riscv_probe,
	.remove = optee_riscv_remove,
};

int optee_riscv_abi_register(void)
{
	return platform_driver_register(&optee_riscv_driver);
}

void optee_riscv_abi_unregister(void)
{
	platform_driver_unregister(&optee_riscv_driver);
}
