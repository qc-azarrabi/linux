/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
/*
 * Copyright (c) 2015-2021, Linaro Limited
 */
#ifndef OPTEE_CONDUIT_H
#define OPTEE_CONDUIT_H

#include <linux/device.h>

struct optee_conduit_res {
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
};

#define OPTEE_RES_MEMBER_MATCH(t, m)					\
	BUILD_BUG_ON(offsetof(struct optee_conduit_res, m) !=		\
		     offsetof(t, m));					\
	BUILD_BUG_ON(sizeof_field(struct optee_conduit_res, m) !=	\
		     sizeof_field(t, m))

#define OPTEE_CONDUIT_RES_MATCH(t)					\
	do {								\
		BUILD_BUG_ON(sizeof(struct optee_conduit_res) !=	\
			     sizeof(t));				\
		OPTEE_RES_MEMBER_MATCH(t, a0);				\
		OPTEE_RES_MEMBER_MATCH(t, a1);				\
		OPTEE_RES_MEMBER_MATCH(t, a2);				\
		OPTEE_RES_MEMBER_MATCH(t, a3);				\
	} while (0)

typedef void (optee_invoke_fn)(unsigned long, unsigned long, unsigned long,
			       unsigned long, unsigned long, unsigned long,
			       unsigned long, unsigned long,
			       struct optee_conduit_res *);

#if defined(CONFIG_HAVE_ARM_SMCCC) || defined(CONFIG_RISCV_SBI_MPXY_MBOX)

optee_invoke_fn *arch_get_invoke_func(struct device *dev);

#else

static inline optee_invoke_fn *arch_get_invoke_func(struct device *dev)
{
	return NULL;
}

#endif /* CONFIG_HAVE_ARM_SMCCC || CONFIG_RISCV_SBI_MPXY_MBOX */

#endif /* OPTEE_CONDUIT_H */
