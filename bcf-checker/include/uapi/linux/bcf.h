#ifndef _UAPI__LINUX_BCF_H__
#define _UAPI__LINUX_BCF_H__

#include <linux/types.h>

#define BCF_TYPE_MASK		0x07
#define BCF_OP_MASK		0xf8

/* Expression Types */
#define BCF_TYPE(code)		((code) & BCF_TYPE_MASK)
#define BCF_BV			0x00	/* Bitvector */
#define BCF_BOOL		0x01	/* Boolean */
#define BCF_LIST		0x02	/* List */

/* Extract operation from code */
#define BCF_OP(code)		((code) & BCF_OP_MASK)

/* Common Operations */
#define BCF_VAL			0x08	/* Value/Constant */
#define BCF_VAR			0x18	/* Variable */
#define BCF_ITE			0x28	/* If-Then-Else */

/* Bitvector Operations */
#define BCF_SDIV		0xb0	/* Signed division */
#define BCF_SMOD		0xd0	/* Signed modulo */
#define BCF_EXTRACT		0x38	/* Bit extraction */
#define BCF_SIGN_EXTEND		0x48	/* Sign extension */
#define BCF_ZERO_EXTEND		0x58	/* Zero extension */
#define BCF_CONCAT		0x68	/* Concatenation */
#define BCF_BVSIZE		0x78	/* Bitvector size */
#define BCF_FROM_BOOL		0x88	/* Bool list to Bitvector */

/* Boolean Operations */
#define BCF_CONJ		0x00	/* Conjunction (AND) */
#define BCF_DISJ		0x40	/* Disjunction (OR) */
#define BCF_DISTINCT		0x50	/* Distinct predicate */
#define BCF_NOT			0x80	/* Negation */
#define BCF_IMPLIES		0x90	/* Implication */
#define BCF_XOR			0x38	/* Exclusive OR */
#define BCF_BITOF		0x48	/* Bitvector to Boolean */

/* Boolean Literals */
#define BCF_TRUE		0x00
#define BCF_FALSE		0x01

/**
 * struct bcf_expr - BCF expression structure
 * @code: Operation code (type | operation)
 * @vlen: Argument count
 * @params: Operation parameters
 * @args: Argument indices
 *
 * Parameter encoding by type:
 * - Bitvector: [7:0] bit width, except EXTRACT/EXTEND use [15:8] for additional info
 * - Boolean: [0] literal value for constants
 * - List: element type encoding
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
#define BCF_BOOL_LITERAL(p)	((p) & 1)
#define BCF_BITOF_BIT(p)	BCF_PARAM_HIGH(p)

struct bcf_conds {
	__s32	path_cond;
	__s32	refine_cond;
};

#define BCF_MAGIC		0x0BCF

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

/* Rule Classification */
#define BCF_RULE_CLASS(r)	((r) & 0xe000)
#define BCF_RULE_CORE		0x0000
#define BCF_RULE_BOOL		0x2000
#define BCF_RULE_BV		0x4000

#define BCF_STEP_RULE(r)	((r) & 0x1fff)

/* Core Proof Rules */
enum {
	BCF_RULE_ASSUME,

	/* Rewrite with lemmas */
	BCF_RULE_INSTANTIATION,

	/* Equality */
	BCF_RULE_REFL,
	BCF_RULE_SYMM,
	BCF_RULE_TRANS,
	BCF_RULE_CONG,
	BCF_RULE_TRUE_INTRO,
	BCF_RULE_TRUE_ELIM,
	BCF_RULE_FALSE_INTRO,
	BCF_RULE_FALSE_ELIM,
	__MAX_BCF_CORE_RULES,
};

/* Boolean Proof Rules */
enum {
	BCF_RULE_RESOLUTION,
	BCF_RULE_FACTORING,
	BCF_RULE_REORDERING,
	BCF_RULE_SPLIT,
	BCF_RULE_EQ_RESOLVE,
	BCF_RULE_MODUS_PONENS,
	BCF_RULE_NOT_NOT_ELIM,
	BCF_RULE_CONTRA,

	BCF_RULE_AND_ELIM,
	BCF_RULE_AND_INTRO,
	BCF_RULE_NOT_OR_ELIM,
	BCF_RULE_IMPLIES_ELIM,
	BCF_RULE_NOT_IMPLIES_ELIM,
	BCF_RULE_EQUIV_ELIM,
	BCF_RULE_NOT_EQUIV_ELIM,
	BCF_RULE_XOR_ELIM,
	BCF_RULE_NOT_XOR_ELIM,
	BCF_RULE_ITE_ELIM,
	BCF_RULE_NOT_ITE_ELIM,
	BCF_RULE_NOT_AND,

	/* CNF Transformation */
	BCF_RULE_CNF_AND_POS,
	BCF_RULE_CNF_AND_NEG,
	BCF_RULE_CNF_OR_POS,
	BCF_RULE_CNF_OR_NEG,
	BCF_RULE_CNF_IMPLIES_POS,
	BCF_RULE_CNF_IMPLIES_NEG,
	BCF_RULE_CNF_EQUIV_POS,
	BCF_RULE_CNF_EQUIV_NEG,
	BCF_RULE_CNF_XOR_POS,
	BCF_RULE_CNF_XOR_NEG,
	BCF_RULE_CNF_ITE_POS,
	BCF_RULE_CNF_ITE_NEG,
	BCF_RULE_ITE_EQ,
	__MAX_BCF_BOOL_RULES,
};

/* Bitvector Proof Rules */
enum {
	BCF_RULE_BITBLAST,	/* Convert a bv formula to a boolean circuit */
	__MAX_BCF_BV_RULES,
};

#endif /* _UAPI__LINUX_BCF_H__ */
