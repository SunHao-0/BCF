/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI__LINUX_BCF_H__
#define _UAPI__LINUX_BCF_H__

#include <linux/types.h>
#include <linux/bpf.h>

// clang-format off

/* Expression Types */
#define BCF_TYPE(code)	((code) & 0x07)
#define BCF_BV		0x00 /* Bitvector */
#define BCF_BOOL	0x01 /* Boolean */
#define BCF_LIST	0x02 /* List of vals */
#define __MAX_BCF_TYPE	0x03

#define BCF_OP(code)	((code) & 0xf8)
/* Common Operations */
#define BCF_VAL	0x08 /* Value/Constant */
#define BCF_VAR	0x18 /* Variable */
#define BCF_ITE	0x28 /* If-Then-Else */

/* Bitvector Operations */
#define BCF_SDIV	0xb0
#define BCF_SMOD	0xd0
#define BCF_EXTRACT	0x38 /* Bitvector extraction */
#define BCF_SIGN_EXTEND 0x48 /* Sign extension */
#define BCF_ZERO_EXTEND 0x58 /* Zero extension */
#define BCF_BVSIZE	0x68 /* Bitvector size */
#define BCF_BVNOT	0x78 /* Bitvector not */
#define BCF_FROM_BOOL	0x88 /* Bool list to Bitvector */
#define BCF_CONCAT	0x98 /* Concatenation */
#define BCF_REPEAT	0xa8 /* Bitvector repeat */

/* Boolean Operations */
#define BCF_CONJ	0x00 /* Conjunction (AND) */
#define BCF_DISJ	0x40 /* Disjunction (OR) */
#define BCF_NOT		0x80 /* Negation */
#define BCF_IMPLIES	0x90 /* Implication */
#define BCF_XOR		0x38 /* Exclusive OR */
#define BCF_BITOF	0x48 /* Bitvector to Boolean */

/* Boolean Literals/Vals */
#define BCF_FALSE	0x00
#define BCF_TRUE	0x01

/*
 * struct bcf_expr - BCF expression structure
 * @code: Operation code (operation | type)
 * @vlen: Argument count
 * @params: Operation parameters
 * @args: Argument indices
 *
 * Parameter encoding by type:
 * - Bitvector: [7:0] bit width, except:
 *	- [15:8] and [7:0] extract `start` and `end` for EXTRACT;
 *	- [15:8] repeat count for REPEAT;
 *	- [15:8] extension size for SIGN/ZERO_EXTEND
 * - Boolean:
 *	- [0] literal value for constants;
 *	- [7:0] bit index for BITOF.
 * - List: element type encoding:
 *	- [7:0] for types;
 *	- [15:8] for type parameters, e.g., bit width.
 */
struct bcf_expr {
	__u8	code;
	__u8	vlen;
	__u16	params;
	__u32	args[];
};

#define BCF_PARAM_LOW(p)	((p) & 0xff)
#define BCF_PARAM_HIGH(p)	(((p) >> 8) & 0xff)

/* Operation-specific parameter meanings */
#define BCF_BV_WIDTH(p)		BCF_PARAM_LOW(p)
#define BCF_EXT_LEN(p)		BCF_PARAM_HIGH(p)
#define BCF_EXTRACT_START(p)	BCF_PARAM_HIGH(p)
#define BCF_EXTRACT_END(p)	BCF_PARAM_LOW(p)
#define BCF_REPEAT_N(p)		BCF_PARAM_HIGH(p)
#define BCF_BOOL_LITERAL(p)	((p) & 1)
#define BCF_BITOF_BIT(p)	BCF_PARAM_LOW(p)
#define BCF_LIST_TYPE(p)	BCF_PARAM_LOW(p)
#define BCF_LIST_TYPE_PARAM(p)	BCF_PARAM_HIGH(p)

/* BCF proof format definitions */
#define BCF_MAGIC	0x0BCF

struct bcf_proof_header {
	__u32	magic;
	__u32	expr_cnt;
	__u32	step_cnt;
};

/**
 * struct bcf_proof_step - Proof step
 * @rule: Rule identifier (class | rule)
 * @premise_cnt: Number of premises
 * @param_cnt: Number of parameters
 * @args: Arguments (premises followed by parameters)
 */
struct bcf_proof_step {
	__u16	rule;
	__u8	premise_cnt;
	__u8	param_cnt;
	__u32	args[];
};

/* Rule Class */
#define BCF_RULE_CLASS(r)	((r) & 0xe000)
#define BCF_RULE_CORE		0x0000
#define BCF_RULE_BOOL		0x2000
#define BCF_RULE_BV		0x4000

#define BCF_STEP_RULE(r)	((r) & 0x1fff)

/* Core proof rules */
#define BCF_CORE_RULES(FN)  \
	FN(ASSUME)          \
	FN(EVALUATE)        \
	FN(DISTINCT_VALUES) \
	FN(ACI_NORM)        \
	FN(ABSORB)          \
	FN(REWRITE)         \
	FN(REFL)            \
	FN(SYMM)            \
	FN(TRANS)           \
	FN(CONG)            \
	FN(TRUE_INTRO)      \
	FN(TRUE_ELIM)       \
	FN(FALSE_INTRO)     \
	FN(FALSE_ELIM)

#define BCF_RULE_NAME(x) BCF_RULE_##x
#define BCF_RULE_ENUM_VARIANT(x) BCF_RULE_NAME(x),

enum bcf_core_rule {
	BCF_RULE_CORE_UNSPEC = 0,
	BCF_CORE_RULES(BCF_RULE_ENUM_VARIANT)
	__MAX_BCF_CORE_RULES,
};

/* Boolean proof rules */
#define BCF_BOOL_RULES(FN)   \
	FN(RESOLUTION)       \
	FN(FACTORING)        \
	FN(REORDERING)       \
	FN(SPLIT)            \
	FN(EQ_RESOLVE)       \
	FN(MODUS_PONENS)     \
	FN(NOT_NOT_ELIM)     \
	FN(CONTRA)           \
	FN(AND_ELIM)         \
	FN(AND_INTRO)        \
	FN(NOT_OR_ELIM)      \
	FN(IMPLIES_ELIM)     \
	FN(NOT_IMPLIES_ELIM) \
	FN(EQUIV_ELIM)       \
	FN(NOT_EQUIV_ELIM)   \
	FN(XOR_ELIM)         \
	FN(NOT_XOR_ELIM)     \
	FN(ITE_ELIM)         \
	FN(NOT_ITE_ELIM)     \
	FN(NOT_AND)          \
	FN(CNF_AND_POS)      \
	FN(CNF_AND_NEG)      \
	FN(CNF_OR_POS)       \
	FN(CNF_OR_NEG)       \
	FN(CNF_IMPLIES_POS)  \
	FN(CNF_IMPLIES_NEG)  \
	FN(CNF_EQUIV_POS)    \
	FN(CNF_EQUIV_NEG)    \
	FN(CNF_XOR_POS)      \
	FN(CNF_XOR_NEG)      \
	FN(CNF_ITE_POS)      \
	FN(CNF_ITE_NEG)      \
	FN(ITE_EQ)

enum bcf_bool_rule {
	BCF_RULE_BOOL_UNSPEC = 0,
	BCF_BOOL_RULES(BCF_RULE_ENUM_VARIANT)
	__MAX_BCF_BOOL_RULES,
};

/* Bitvector proof rules */
#define BCF_BV_RULES(FN) \
	FN(BITBLAST)     \
	FN(POLY_NORM)    \
	FN(POLY_NORM_EQ)

enum bcf_bv_rule {
	BCF_RULE_BV_UNSPEC = 0,
	BCF_BV_RULES(BCF_RULE_ENUM_VARIANT)
	__MAX_BCF_BV_RULES,
};
#undef BCF_RULE_ENUM_VARIANT

#define BCF_REWRITE_NAME(x)	BCF_REWRITE_##x
#define BCF_REWRITES_TABLE(FN)		\
	FN(EQ_REFL)			\
	FN(EQ_SYMM)			\
	FN(EQ_COND_DEQ)			\
	FN(EQ_ITE_LIFT)			\
	FN(DISTINCT_BINARY_ELIM)	\
	FN(ITE_TRUE_COND)		\
	FN(ITE_FALSE_COND)		\
	FN(ITE_NOT_COND)		\
	FN(ITE_EQ_BRANCH)		\
	FN(ITE_THEN_LOOKAHEAD)		\
	FN(ITE_ELSE_LOOKAHEAD)		\
	FN(ITE_THEN_NEG_LOOKAHEAD)	\
	FN(ITE_ELSE_NEG_LOOKAHEAD)	\
	FN(BOOL_DOUBLE_NOT_ELIM)	\
	FN(BOOL_NOT_TRUE)		\
	FN(BOOL_NOT_FALSE)		\
	FN(BOOL_EQ_TRUE)		\
	FN(BOOL_EQ_FALSE)		\
	FN(BOOL_EQ_NREFL)		\
	FN(BOOL_IMPL_FALSE1)		\
	FN(BOOL_IMPL_FALSE2)		\
	FN(BOOL_IMPL_TRUE1)		\
	FN(BOOL_IMPL_TRUE2)		\
	FN(BOOL_IMPL_ELIM)		\
	FN(BOOL_DUAL_IMPL_EQ)		\
	FN(BOOL_AND_CONF)		\
	FN(BOOL_AND_CONF2)		\
	FN(BOOL_OR_TAUT)		\
	FN(BOOL_OR_TAUT2)		\
	FN(BOOL_IMPLIES_DE_MORGAN)	\
	FN(BOOL_XOR_REFL)		\
	FN(BOOL_XOR_NREFL)		\
	FN(BOOL_XOR_FALSE)		\
	FN(BOOL_XOR_TRUE)		\
	FN(BOOL_XOR_COMM)		\
	FN(BOOL_XOR_ELIM)		\
	FN(BOOL_NOT_XOR_ELIM)		\
	FN(BOOL_NOT_EQ_ELIM1)		\
	FN(BOOL_NOT_EQ_ELIM2)		\
	FN(ITE_NEG_BRANCH)		\
	FN(ITE_THEN_TRUE)		\
	FN(ITE_ELSE_FALSE)		\
	FN(ITE_THEN_FALSE)		\
	FN(ITE_ELSE_TRUE)		\
	FN(ITE_THEN_LOOKAHEAD_SELF)	\
	FN(ITE_ELSE_LOOKAHEAD_SELF)	\
	FN(ITE_THEN_LOOKAHEAD_NOT_SELF)	\
	FN(ITE_ELSE_LOOKAHEAD_NOT_SELF)	\
	FN(ITE_EXPAND)			\
	FN(BOOL_NOT_ITE_ELIM)		\
	FN(BV_CONCAT_EXTRACT_MERGE)	\
	FN(BV_EXTRACT_EXTRACT)		\
	FN(BV_EXTRACT_WHOLE)		\
	FN(BV_EXTRACT_CONCAT_1)		\
	FN(BV_EXTRACT_CONCAT_2)		\
	FN(BV_EXTRACT_CONCAT_3)		\
	FN(BV_EXTRACT_CONCAT_4)		\
	FN(BV_EQ_EXTRACT_ELIM1)		\
	FN(BV_EQ_EXTRACT_ELIM2)		\
	FN(BV_EQ_EXTRACT_ELIM3)		\
	FN(BV_EXTRACT_NOT)		\
	FN(BV_EXTRACT_SIGN_EXTEND_1)	\
	FN(BV_EXTRACT_SIGN_EXTEND_2)	\
	FN(BV_EXTRACT_SIGN_EXTEND_3)	\
	FN(BV_NOT_XOR)			\
	FN(BV_AND_SIMPLIFY_1)		\
	FN(BV_AND_SIMPLIFY_2)		\
	FN(BV_OR_SIMPLIFY_1)		\
	FN(BV_OR_SIMPLIFY_2)		\
	FN(BV_XOR_SIMPLIFY_2)		\
	FN(BV_XOR_SIMPLIFY_3)		\
	FN(BV_ULT_ADD_ONE)		\
	FN(BV_MULT_SLT_MULT_1)		\
	FN(BV_MULT_SLT_MULT_2)		\
	FN(BV_COMMUTATIVE_XOR)		\
	FN(BV_ZERO_EXTEND_ELIMINATE_0)	\
	FN(BV_SIGN_EXTEND_ELIMINATE_0)	\
	FN(BV_NOT_NEQ)			\
	FN(BV_ULT_ONES)			\
	FN(BV_CONCAT_MERGE_CONST)	\
	FN(BV_COMMUTATIVE_ADD)		\
	FN(BV_SUB_ELIMINATE)		\
	FN(BV_ITE_WIDTH_ONE)		\
	FN(BV_ITE_WIDTH_ONE_NOT)	\
	FN(BV_EQ_XOR_SOLVE)		\
	FN(BV_EQ_NOT_SOLVE)		\
	FN(BV_UGT_ELIMINATE)		\
	FN(BV_UGE_ELIMINATE)		\
	FN(BV_SGT_ELIMINATE)		\
	FN(BV_SGE_ELIMINATE)		\
	FN(BV_SLE_ELIMINATE)		\
	FN(BV_ULE_ELIMINATE)		\
	FN(BV_ZERO_EXTEND_ELIMINATE)	\
	FN(BV_ITE_EQUAL_CHILDREN)	\
	FN(BV_ITE_CONST_CHILDREN_1)	\
	FN(BV_ITE_CONST_CHILDREN_2)	\
	FN(BV_ITE_EQUAL_COND_1)		\
	FN(BV_ITE_EQUAL_COND_2)		\
	FN(BV_ITE_EQUAL_COND_3)		\
	FN(BV_ITE_MERGE_THEN_IF)	\
	FN(BV_ITE_MERGE_ELSE_IF)	\
	FN(BV_ITE_MERGE_THEN_ELSE)	\
	FN(BV_ITE_MERGE_ELSE_ELSE)	\
	FN(BV_SHL_BY_CONST_0)		\
	FN(BV_SHL_BY_CONST_1)		\
	FN(BV_SHL_BY_CONST_2)		\
	FN(BV_LSHR_BY_CONST_0)		\
	FN(BV_LSHR_BY_CONST_1)		\
	FN(BV_LSHR_BY_CONST_2)		\
	FN(BV_ASHR_BY_CONST_0)		\
	FN(BV_ASHR_BY_CONST_1)		\
	FN(BV_ASHR_BY_CONST_2)		\
	FN(BV_AND_CONCAT_PULLUP)	\
	FN(BV_OR_CONCAT_PULLUP)		\
	FN(BV_XOR_CONCAT_PULLUP)	\
	FN(BV_AND_CONCAT_PULLUP2)	\
	FN(BV_OR_CONCAT_PULLUP2)	\
	FN(BV_XOR_CONCAT_PULLUP2)	\
	FN(BV_AND_CONCAT_PULLUP3)	\
	FN(BV_OR_CONCAT_PULLUP3)	\
	FN(BV_XOR_CONCAT_PULLUP3)	\
	FN(BV_XOR_DUPLICATE)		\
	FN(BV_XOR_ONES)			\
	FN(BV_ULE_MAX)			\
	FN(BV_XOR_NOT)			\
	FN(BV_NOT_IDEMP)		\
	FN(BV_ULT_ZERO_1)		\
	FN(BV_ULT_ZERO_2)		\
	FN(BV_ULT_SELF)			\
	FN(BV_LT_SELF)			\
	FN(BV_ULE_SELF)			\
	FN(BV_ULE_ZERO)			\
	FN(BV_ZERO_ULE)			\
	FN(BV_SLE_SELF)			\
	FN(BV_NOT_ULT)			\
	FN(BV_SHL_ZERO)			\
	FN(BV_LSHR_ZERO)		\
	FN(BV_ASHR_ZERO)		\
	FN(BV_ULT_ONE)			\
	FN(BV_MERGE_SIGN_EXTEND_1)	\
	FN(BV_MERGE_SIGN_EXTEND_2)	\
	FN(BV_SIGN_EXTEND_EQ_CONST_1)	\
	FN(BV_SIGN_EXTEND_EQ_CONST_2)	\
	FN(BV_ZERO_EXTEND_EQ_CONST_1)	\
	FN(BV_ZERO_EXTEND_EQ_CONST_2)	\
	FN(BV_ZERO_EXTEND_ULT_CONST_1)	\
	FN(BV_ZERO_EXTEND_ULT_CONST_2)	\
	FN(BV_SIGN_EXTEND_ULT_CONST_1)	\
	FN(BV_SIGN_EXTEND_ULT_CONST_2)	\
	FN(BV_SIGN_EXTEND_ULT_CONST_3)	\
	FN(BV_SIGN_EXTEND_ULT_CONST_4)

#define BCF_REWRITE_ENUM_VARIANT(x) BCF_REWRITE_NAME(x),
enum bcf_rewrite_id {
	BCF_REWRITE_UNSPEC = 0,
	BCF_REWRITES_TABLE(BCF_REWRITE_ENUM_VARIANT)
	__MAX_BCF_REWRITES,
};
#undef BCF_REWRITE_ENUM_VARIANT
// clang-format on

#endif /* _UAPI__LINUX_BCF_H__ */
