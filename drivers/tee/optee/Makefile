# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_OPTEE) += optee.o
optee-objs += core.o
optee-objs += call.o
optee-objs += notif.o
optee-objs += rpc.o
optee-objs += protmem.o
optee-objs += supp.o
optee-objs += device.o
optee-$(CONFIG_HAVE_ARM_SMCCC) += conduit_arm.o
optee-$(CONFIG_RISCV_SBI_MPXY_MBOX) += conduit_riscv.o
optee-objs += optee_abi.o
optee-$(CONFIG_ARM_FFA_TRANSPORT) += ffa_abi.o

# for tracing framework to find optee_trace.h
CFLAGS_optee_abi.o := -I$(src)
