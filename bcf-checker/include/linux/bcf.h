/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_BCF_H__
#define __LINUX_BCF_H__

#include <uapi/linux/bcf.h>
#include <uapi/linux/bpf.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/bpfptr.h>
#include <linux/bpf_verifier.h>
#include <linux/kernel.h>

static_assert(sizeof(struct bcf_expr) == sizeof(u32));

struct bcf_expr_unary {
	u8 code;
	u8 vlen;
	u16 params;
	u32 arg0;
};

static_assert(sizeof(struct bcf_expr_unary) == sizeof(u32) * 2);

struct bcf_expr_binary {
	u8 code;
	u8 vlen;
	u16 params;
	u32 arg0;
	u32 arg1;
};

static_assert(sizeof(struct bcf_expr_binary) == sizeof(u32) * 3);

struct bcf_expr_ternary {
	u8 code;
	u8 vlen;
	u16 params;
	u32 arg0;
	u32 arg1;
	u32 arg2;
};

static_assert(sizeof(struct bcf_expr_ternary) == sizeof(u32) * 4);

#define BCF_PRED_VAR                                  \
	((struct bcf_expr){                           \
		.code = BCF_BOOL_PRED | BCF_BOOL_VAR, \
		.vlen = 0,                            \
		.params = 0,                          \
	})

#define BCF_PRED_TRUE                                 \
	((struct bcf_expr){                           \
		.code = BCF_BOOL_PRED | BCF_BOOL_VAL, \
		.vlen = 0,                            \
		.params = BCF_BOOL_TRUE,              \
	})

#define BCF_PRED_FALSE                                \
	((struct bcf_expr){                           \
		.code = BCF_BOOL_PRED | BCF_BOOL_VAL, \
		.vlen = 0,                            \
		.params = BCF_BOOL_FALSE,             \
	})

#define BCF_PRED_NOT(ARG0)                       \
	((struct bcf_expr_unary){                \
		.code = BCF_BOOL_PRED | BCF_NOT, \
		.vlen = 1,                       \
		.params = 0,                     \
		.arg0 = ARG0,                    \
	})

#define BCF_PRED_ITE(ARG0, ARG1, ARG2)           \
	((struct bcf_expr_ternary){              \
		.code = BCF_BOOL_PRED | BCF_ITE, \
		.vlen = 3,                       \
		.params = 0,                     \
		.arg0 = ARG0,                    \
		.arg1 = ARG1,                    \
		.arg2 = ARG2,                    \
	})

#define BCF_BOOL_EXPR(OP, ARG0, ARG1)       \
	((struct bcf_expr_binary){          \
		.code = BCF_BOOL_PRED | OP, \
		.vlen = 2,                  \
		.params = 0,                \
		.arg0 = ARG0,               \
		.arg1 = ARG1,               \
	})

#define BCF_PRED_EQUIV(ARG0, ARG1) BCF_BOOL_EXPR(BCF_EQUIV, ARG0, ARG1)
#define BCF_PRED_XOR(ARG0, ARG1) BCF_BOOL_EXPR(BCF_XOR, ARG0, ARG1)
#define BCF_PRED_IMPLES(ARG0, ARG1) BCF_BOOL_EXPR(BCF_IMPLIES, ARG0, ARG1)

#define BCF_BV_VAR_SZ(SZ)					\
	((struct bcf_expr){                                \
		.code = BCF_BV_ALU | BCF_EXT | BCF_BV_VAR, \
		.vlen = 0,                                 \
		.params = SZ,                              \
	})

#define BCF_BV_VAR32                                       \
	((struct bcf_expr){                                \
		.code = BCF_BV_ALU | BCF_EXT | BCF_BV_VAR, \
		.vlen = 0,                                 \
		.params = 32,                              \
	})

#define BCF_BV_VAR64                                       \
	((struct bcf_expr){                                \
		.code = BCF_BV_ALU | BCF_EXT | BCF_BV_VAR, \
		.vlen = 0,                                 \
		.params = 64,                              \
	})

#define BCF_BV_VAL32(IMM)                                  \
	((struct bcf_expr_unary){                          \
		.code = BCF_BV_ALU | BCF_EXT | BCF_BV_VAL, \
		.vlen = 1,                                 \
		.params = 32,                              \
		.arg0 = IMM,                               \
	})

#define BCF_BV_VAL64(IMM)                                  \
	((struct bcf_expr_binary){                         \
		.code = BCF_BV_ALU | BCF_EXT | BCF_BV_VAL, \
		.vlen = 2,                                 \
		.params = 64,                              \
		.arg0 = IMM,                               \
		.arg1 = (u64)IMM >> 32,                    \
	})

#define BCF_BV_EXTRACT(SIZE, ARG0)                          \
	((struct bcf_expr_unary){                           \
		.code = BCF_BV_ALU | BCF_EXT | BCF_EXTRACT, \
		.vlen = 1,                                  \
		.params = ((u16)SIZE - 1) << 8 | 0,         \
		.arg0 = ARG0,                               \
	})

#define BCF_BV_ZEXT(SIZE, BITSZ, ARG0)                          \
	((struct bcf_expr_unary){                               \
		.code = BCF_BV_ALU | BCF_EXT | BCF_ZERO_EXTEND, \
		.vlen = 1,                                      \
		.params = (u16)SIZE << 8 | BITSZ,               \
		.arg0 = ARG0,                                   \
	})

#define BCF_BV_SEXT(SIZE, BITSZ, ARG0)                          \
	((struct bcf_expr_unary){                               \
		.code = BCF_BV_ALU | BCF_EXT | BCF_SIGN_EXTEND, \
		.vlen = 1,                                      \
		.params = (u16)SIZE << 8 | BITSZ,               \
		.arg0 = ARG0,                                   \
	})

#define BCF_BV_EXPR(CODE, ARG0, ARG1, BITS) \
	((struct bcf_expr_binary){          \
		.code = CODE,               \
		.vlen = 2,                  \
		.params = BITS,             \
		.arg0 = ARG0,               \
		.arg1 = ARG1,               \
	})

#define BCF_ALU(OP, ARG0, ARG1, BITS) \
	BCF_BV_EXPR(BCF_BV_ALU | OP, ARG0, ARG1, BITS)

#define BCF_ALU32(OP, ARG0, ARG1) BCF_ALU(OP, ARG0, ARG1, 32)
#define BCF_ALU64(OP, ARG0, ARG1) BCF_ALU(OP, ARG0, ARG1, 64)

#define BCF_PRED(OP, ARG0, ARG1, BITS) \
	BCF_BV_EXPR(BCF_BV_PRED | OP, ARG0, ARG1, BITS)

#define BCF_PRED32(OP, ARG0, ARG1) BCF_PRED(OP, ARG0, ARG1, 32)
#define BCF_PRED64(OP, ARG0, ARG1) BCF_PRED(OP, ARG0, ARG1, 64)

#define MAX_BCF_PROOF_SIZE BPF_COMPLEXITY_LIMIT_INSNS

static_assert(sizeof(struct bcf_proof_step) == sizeof(u32));

static_assert(__MAX_BCF_BUILTIN_RULES <= MAX_BCF_CLASS_RULES);
static_assert(__MAX_BCF_BOOLEAN_RULES <= MAX_BCF_CLASS_RULES);
static_assert(__MAX_BCF_EQUALITY_RULES <= MAX_BCF_CLASS_RULES);
static_assert(__MAX_BCF_BV_RULES <= MAX_BCF_CLASS_RULES);

int bcf_check_proof(struct bpf_verifier_env *verifier_env, union bpf_attr *attr,
		    bpfptr_t uattr);

#endif /* __LINUX_BCF_H__ */
