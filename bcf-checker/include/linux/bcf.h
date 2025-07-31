/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __LINUX_BCF_H__
#define __LINUX_BCF_H__

#include <uapi/linux/bcf.h>
#include <uapi/linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/bpfptr.h>
#include <linux/bpf.h>
#include <linux/overflow.h>
#include <linux/types.h>

/* Fixed-size expression structures for common cases */
struct bcf_expr_unary {
	u8 code;
	u8 vlen;
	u16 params;
	u32 arg0;
};

struct bcf_expr_binary {
	u8 code;
	u8 vlen;
	u16 params;
	union {
		u32 args[2];
		struct {
			u32 arg0;
			u32 arg1;
		};
	};
};

struct bcf_expr_ternary {
	u8 code;
	u8 vlen;
	u16 params;
	union {
		u32 args[3];
		struct {
			u32 arg0;
			u32 arg1;
			u32 arg2;
		};
	};
};

struct bcf_expr_buf {
	u8 code;
	u8 vlen;
	u16 params;
	u32 args[U8_MAX];
};

static_assert(sizeof(struct bcf_expr) == sizeof(u32));
static_assert(sizeof(struct bcf_expr_unary) ==
	      struct_size_t(struct bcf_expr, args, 1));
static_assert(sizeof(struct bcf_expr_binary) ==
	      struct_size_t(struct bcf_expr, args, 2));
static_assert(sizeof(struct bcf_expr_ternary) ==
	      struct_size_t(struct bcf_expr, args, 3));

static_assert(sizeof(struct bcf_proof_step) == sizeof(u32));

/* Bitvector variable constructors */
#define BCF_BV_VAR(width)                 \
	((struct bcf_expr){               \
		.code = BCF_BV | BCF_VAR, \
		.vlen = 0,                \
		.params = (width),        \
	})

#define BCF_BV_VAR32 BCF_BV_VAR(32)
#define BCF_BV_VAR64 BCF_BV_VAR(64)

/* Bitvector value constructors */
#define BCF_BV_VAL32(imm)                 \
	((struct bcf_expr_unary){         \
		.code = BCF_BV | BCF_VAL, \
		.vlen = 1,                \
		.params = 32,             \
		.arg0 = (imm),            \
	})

#define BCF_BV_VAL64(imm)                   \
	((struct bcf_expr_binary){          \
		.code = BCF_BV | BCF_VAL,   \
		.vlen = 2,                  \
		.params = 64,               \
		.arg0 = (u32)(imm),         \
		.arg1 = (u32)((imm) >> 32), \
	})

/* Bitvector extraction (end bit is 0, start bit is size-1) */
#define BCF_BV_EXTRACT(size, arg)              \
	((struct bcf_expr_unary){              \
		.code = BCF_BV | BCF_EXTRACT,  \
		.vlen = 1,                     \
		.params = (((size) - 1) << 8), \
		.arg0 = (arg),                 \
	})

/* Bitvector extensions */
#define BCF_BV_ZEXT(width, ext_width, arg)              \
	((struct bcf_expr_unary){                       \
		.code = BCF_BV | BCF_ZERO_EXTEND,       \
		.vlen = 1,                              \
		.params = ((ext_width) << 8 | (width)), \
		.arg0 = (arg),                          \
	})

#define BCF_BV_SEXT(width, ext_width, arg)              \
	((struct bcf_expr_unary){                       \
		.code = BCF_BV | BCF_SIGN_EXTEND,       \
		.vlen = 1,                              \
		.params = ((ext_width) << 8 | (width)), \
		.arg0 = (arg),                          \
	})

/* Generic bitvector binary operation */
#define BCF_BV_BINOP(op, width, a0, a1) \
	((struct bcf_expr_binary){      \
		.code = BCF_BV | (op),  \
		.vlen = 2,              \
		.params = (width),      \
		.arg0 = (a0),           \
		.arg1 = (a1),           \
	})

/* Convenience macros for common bit widths */
#define BCF_ALU32(op, a0, a1) BCF_BV_BINOP(op, 32, a0, a1)
#define BCF_ALU64(op, a0, a1) BCF_BV_BINOP(op, 64, a0, a1)

/* Boolean variable constructor */
#define BCF_BOOL_VAR                        \
	((struct bcf_expr){                 \
		.code = BCF_BOOL | BCF_VAR, \
		.vlen = 0,                  \
		.params = 0,                \
	})

/* Boolean literal constructors */
#define BCF_BOOL_TRUE                       \
	((struct bcf_expr){                 \
		.code = BCF_BOOL | BCF_VAL, \
		.vlen = 0,                  \
		.params = BCF_TRUE,         \
	})

#define BCF_BOOL_FALSE                      \
	((struct bcf_expr){                 \
		.code = BCF_BOOL | BCF_VAL, \
		.vlen = 0,                  \
		.params = BCF_FALSE,        \
	})

/* Boolean unary operations */
#define BCF_BOOL_NOT(arg)                   \
	((struct bcf_expr_unary){           \
		.code = BCF_BOOL | BCF_NOT, \
		.vlen = 1,                  \
		.params = 0,                \
		.arg0 = (arg),              \
	})

/* Boolean binary operations */
#define BCF_BOOL_AND(a0, a1)                 \
	((struct bcf_expr_binary){           \
		.code = BCF_BOOL | BCF_CONJ, \
		.vlen = 2,                   \
		.params = 0,                 \
		.arg0 = (a0),                \
		.arg1 = (a1),                \
	})

#define BCF_BOOL_OR(a0, a1)                  \
	((struct bcf_expr_binary){           \
		.code = BCF_BOOL | BCF_DISJ, \
		.vlen = 2,                   \
		.params = 0,                 \
		.arg0 = (a0),                \
		.arg1 = (a1),                \
	})

#define BCF_BOOL_XOR(a0, a1)                \
	((struct bcf_expr_binary){          \
		.code = BCF_BOOL | BCF_XOR, \
		.vlen = 2,                  \
		.params = 0,                \
		.arg0 = (a0),               \
		.arg1 = (a1),               \
	})

#define BCF_BOOL_IMPLIES(a0, a1)                \
	((struct bcf_expr_binary){              \
		.code = BCF_BOOL | BCF_IMPLIES, \
		.vlen = 2,                      \
		.params = 0,                    \
		.arg0 = (a0),                   \
		.arg1 = (a1),                   \
	})

#define BCF_BOOL_DISTINCT(a0, a1)                \
	((struct bcf_expr_binary){               \
		.code = BCF_BOOL | BCF_DISTINCT, \
		.vlen = 2,                       \
		.params = 0,                     \
		.arg0 = (a0),                    \
		.arg1 = (a1),                    \
	})

/* Boolean if-then-else */
#define BCF_BOOL_ITE(cond, then_arg, else_arg) \
	((struct bcf_expr_ternary){            \
		.code = BCF_BOOL | BCF_ITE,    \
		.vlen = 3,                     \
		.params = 0,                   \
		.arg0 = (cond),                \
		.arg1 = (then_arg),            \
		.arg2 = (else_arg),            \
	})

/* Bitvector bit extraction to boolean */
#define BCF_BOOL_BITOF(bit, width, arg)           \
	((struct bcf_expr_unary){                 \
		.code = BCF_BOOL | BCF_BITOF,     \
		.vlen = 1,                        \
		.params = ((bit) << 8 | (width)), \
		.arg0 = (arg),                    \
	})

#define MAX_BCF_PROOF_SIZE (1024 * 1024)

int bcf_check_proof(struct bpf_verifier_env *verifier_env, union bpf_attr *attr,
		    bpfptr_t uattr);

#endif /* __LINUX_BCF_H__ */
