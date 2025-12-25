// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2015-2021, 2023 Linaro Limited
 * Copyright (c) 2016, EPAM Systems
 */

#include <linux/arm-smccc.h>
#include <linux/property.h>
#include "optee_conduit.h"

/* Simple wrapper functions to be able to use as function pointer */
static void optee_smccc_smc(unsigned long a0, unsigned long a1,
			    unsigned long a2, unsigned long a3,
			    unsigned long a4, unsigned long a5,
			    unsigned long a6, unsigned long a7,
			    struct optee_conduit_res *res)
{
	OPTEE_CONDUIT_RES_MATCH(struct arm_smccc_res);
	arm_smccc_smc(a0, a1, a2, a3, a4, a5, a6, a7,
		      (struct arm_smccc_res *)res);
}

static void optee_smccc_hvc(unsigned long a0, unsigned long a1,
			    unsigned long a2, unsigned long a3,
			    unsigned long a4, unsigned long a5,
			    unsigned long a6, unsigned long a7,
			    struct optee_conduit_res *res)
{
	arm_smccc_hvc(a0, a1, a2, a3, a4, a5, a6, a7,
		      (struct arm_smccc_res *)res);
}

optee_invoke_fn *arch_get_invoke_func(struct device *dev)
{
	const char *method;

	pr_info("probing for conduit method.\n");

	if (device_property_read_string(dev, "method", &method)) {
		pr_warn("missing \"method\" property\n");
		return ERR_PTR(-ENXIO);
	}

	if (!strcmp("hvc", method))
		return optee_smccc_hvc;
	else if (!strcmp("smc", method))
		return optee_smccc_smc;

	pr_warn("invalid \"method\" property: %s\n", method);
	return ERR_PTR(-EINVAL);
}
