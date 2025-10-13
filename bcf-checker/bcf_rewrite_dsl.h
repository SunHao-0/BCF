/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __LINUX_BCF_REWRITE_DSL_H__
#define __LINUX_BCF_REWRITE_DSL_H__

#include <uapi/linux/bcf.h>
#include <linux/kernel.h>
#include <linux/args.h>
#include <linux/bpf.h>

struct bcf_expr_nullary {
	u8 code;
	u8 vlen;
	u16 params;
};

/* A macro-based DSL for defining rewrite rules
 *
 * Every rewrite is essentially a lemma, which asserts the eqaulity between
 * lhs and rhs, i.e., lhs can be replaced with rhs (aka rewrite).
 *
 * Two types of rewrites are allowed:
 * 	(1) (rewrite-name, params, lhs, rhs) defined with the REWRITE macro
 * 	(2) (rewrite-name, params, cond, lhs, rhs) by REWRITE_COND
 * The conditional rewrites are applicable only if the `cond` is proved.
 * A rewrite is defined over a list of params of certain types, i.e., it
 * asserts the equality of all terms under that type.
 *
 * The rewrites defined in this file are converted from the RARE rewrites
 * in cvc5, one may refer to the source for higher readability.
 */
struct bcf_rewrite {
	const char *name;
	const struct bcf_expr_nullary *params;
	const struct bcf_expr_nullary *cond;
	const struct bcf_expr_nullary *match;
	const struct bcf_expr_nullary *target;
	u32 id;
	u8 param_cnt;
	u8 cond_len;
	u8 match_len;
	u8 target_len;
};

// clang-format off

#define BCF_ANY __MAX_BCF_TYPE

/* Parameter types allowed, encoded in struct bcf_expr
 * Q    : any type, stands for the question mark `?`;
 * Bool : boolean type;
 * BV(w): bv with `w` bits;
 * BVQ  : bv with arbitrary bits;
 * Bools: list of bools;
 * BVQs : list of BVQ;
 */
#define Q	{ BCF_ANY,  0, 0}
#define Bool	{ BCF_BOOL, 0, 0}
#define BV(w)	{ BCF_BV,   0, ENCODE_PARAM_LOW((w))}
#define Int	BV(32)
#define BVQ	{ BCF_BV,   0, 0 }
#define Bools	{ BCF_LIST, 0, ENCODE_PARAM_LOW(BCF_BOOL)}
#define BVQs	{ BCF_LIST, 0, ENCODE_PARAM_LOW(BCF_BV)}

static inline bool rw_type_any(const struct bcf_expr_nullary *e)
{
	return e->code == BCF_ANY && !e->vlen && !e->params;
}

static inline bool rw_type_bvany(const struct bcf_expr_nullary *e)
{
	return e->code == BCF_BV && !e->vlen && !e->params;
}

#define ENCODE_PARAM_LOW(_v) ((u8)(_v))
#define ENCODE_PARAM_HIGH(_v) ((u16)(_v) << 8)
#define ENCODE_PARAM(_l, _h) (ENCODE_PARAM_LOW((_l)) | ENCODE_PARAM_HIGH((_h)))

static inline bool rw_type_list_bvany(const struct bcf_expr_nullary *e)
{
	return e->code == BCF_LIST && !e->vlen &&
	       e->params == ENCODE_PARAM_LOW(BCF_BV);
}

#define EXPR0(_code, _vlen)		{ (_code), (_vlen), 0 }
#define EXPR1(_code, _vlen, _params)	{ (_code), (_vlen), (_params) }

 /* A variable in an expr refers to a parameter by `idx` */
#define V(idx)	(EXPR1(BCF_VAR, 0, ENCODE_PARAM_LOW((idx))))
#define _TRUE	(EXPR1((BCF_BOOL | BCF_VAL), 0, ENCODE_PARAM_LOW(BCF_TRUE)))
#define _FALSE	(EXPR1((BCF_BOOL | BCF_VAL), 0, ENCODE_PARAM_LOW(BCF_FALSE)))

static inline bool is_rw_var(const struct bcf_expr_nullary *e)
{
	return e->code == BCF_VAR && !e->vlen && !BCF_PARAM_HIGH(e->params);
}

static inline u32 rw_var_id(const struct bcf_expr_nullary *e)
{
	return BCF_PARAM_LOW(e->params);
}

 /* Variadic helpers */
#define FE_1(WHAT, X)		WHAT(X)
#define FE_2(WHAT, X, ...)	WHAT(X), FE_1(WHAT, __VA_ARGS__)
#define FE_3(WHAT, X, ...)	WHAT(X), FE_2(WHAT, __VA_ARGS__)
#define FE_4(WHAT, X, ...)	WHAT(X), FE_3(WHAT, __VA_ARGS__)
#define FE_5(WHAT, X, ...)	WHAT(X), FE_4(WHAT, __VA_ARGS__)
#define FE_6(WHAT, X, ...)	WHAT(X), FE_5(WHAT, __VA_ARGS__)
#define FE_7(WHAT, X, ...)	WHAT(X), FE_6(WHAT, __VA_ARGS__)
#define FE_8(WHAT, X, ...)	WHAT(X), FE_7(WHAT, __VA_ARGS__)
#define FE_9(WHAT, X, ...)	WHAT(X), FE_8(WHAT, __VA_ARGS__)
#define FE_10(WHAT, X, ...)	WHAT(X), FE_9(WHAT, __VA_ARGS__)
#define FE_11(WHAT, X, ...)	WHAT(X), FE_10(WHAT, __VA_ARGS__)
#define FE_12(WHAT, X, ...)	WHAT(X), FE_11(WHAT, __VA_ARGS__)
#define FE_13(WHAT, X, ...)	WHAT(X), FE_12(WHAT, __VA_ARGS__)
#define FE_14(WHAT, X, ...)	WHAT(X), FE_13(WHAT, __VA_ARGS__)
#define FE_15(WHAT, X, ...)	WHAT(X), FE_14(WHAT, __VA_ARGS__)

#define __FOR_EACH_N(N, WHAT, ...) CONCATENATE(FE_, N)(WHAT, __VA_ARGS__)
#define __FOR_EACH(WHAT, ...)	\
	 __FOR_EACH_N(COUNT_ARGS(__VA_ARGS__), WHAT, __VA_ARGS__)

#define __UNTUPLE(...)		__VA_ARGS__
#define __UNTUPLE_ONE(X)	__UNTUPLE X

#define EXPRS(_code, _vlen, ...)	\
	 EXPR0((_code), (_vlen)), __FOR_EACH(__UNTUPLE_ONE, __VA_ARGS__)
#define EXPR1S(_code, _vlen, _param, ...)\
	 EXPR1((_code), (_vlen), (_param)), __FOR_EACH(__UNTUPLE_ONE, __VA_ARGS__)

 /* BOOL expressions */
#define BOOL_EXPRS(_op, ...)	\
	 ( EXPRS((BCF_BOOL | (_op)), COUNT_ARGS(__VA_ARGS__), __VA_ARGS__) )

#define not(X)		BOOL_EXPRS(BCF_NOT, X)
#define ite(C, T, E)	BOOL_EXPRS(BCF_ITE, C, T, E)
#define eq(A, B)	BOOL_EXPRS(BPF_JEQ, A, B)
#define neq(A, B)	BOOL_EXPRS(BPF_JNE, A, B)
#define implies(A, B)	BOOL_EXPRS(BCF_IMPLIES, A, B)
#define conj(...)	BOOL_EXPRS(BCF_CONJ, __VA_ARGS__)
#define disj(...)	BOOL_EXPRS(BCF_DISJ, __VA_ARGS__)
#define xor(...)	BOOL_EXPRS(BCF_XOR, __VA_ARGS__)
#define bitof(X, B)	BOOL_EXPRS(BCF_BITOF, X, B)
#define bvult(A, B)	BOOL_EXPRS(BPF_JLT, A, B)
#define bvule(A, B)	BOOL_EXPRS(BPF_JLE, A, B)
#define bvugt(A, B)	BOOL_EXPRS(BPF_JGT, A, B)
#define bvuge(A, B)	BOOL_EXPRS(BPF_JGE, A, B)
#define bvslt(A, B)	BOOL_EXPRS(BPF_JSLT, A, B)
#define bvsle(A, B)	BOOL_EXPRS(BPF_JSLE, A, B)
#define bvsgt(A, B)	BOOL_EXPRS(BPF_JSGT, A, B)
#define bvsge(A, B)	BOOL_EXPRS(BPF_JSGE, A, B)

 /* BV expressions */
#define BV_EXPRS(_op, ...)	\
	 ( EXPRS((BCF_BV | (_op)), COUNT_ARGS(__VA_ARGS__), __VA_ARGS__) )
#define BV_EXPR1S(_op, _param, ...)	\
	 ( EXPR1S((BCF_BV | (_op)), COUNT_ARGS(__VA_ARGS__), (_param), __VA_ARGS__) )

#define bvadd(...)	BV_EXPRS(BPF_ADD, __VA_ARGS__)
#define bvsub(A, B)	BV_EXPRS(BPF_SUB, A, B)
#define bvmul(...)	BV_EXPRS(BPF_MUL, __VA_ARGS__)
#define bvdiv(A, B)	BV_EXPRS(BPF_DIV, A, B)
#define bvmod(A, B)	BV_EXPRS(BPF_MOD, A, B)
#define bvsdiv(A, B)	BV_EXPRS(BCF_SDIV, A, B)
#define bvsmod(A, B)	BV_EXPRS(BCF_SMOD, A, B)
#define bvneg(X)	BV_EXPRS(BPF_NEG, X)
#define bvshl(X, B)	BV_EXPRS(BPF_LSH, X, B)
#define bvlshr(X, B)	BV_EXPRS(BPF_RSH, X, B)
#define bvashr(X, B)	BV_EXPRS(BPF_ARSH, X, B)
#define bvor(...)	BV_EXPRS(BPF_OR, __VA_ARGS__)
#define bvand(...)	BV_EXPRS(BPF_AND, __VA_ARGS__)
#define bvxor(...)	BV_EXPRS(BPF_XOR, __VA_ARGS__)
#define bvite(C, T, E)	BV_EXPRS(BCF_ITE, C, T, E)
#define bvnot(X)	BV_EXPRS(BCF_BVNOT, X)

#define extract(START, END, X)	BV_EXPRS(BCF_EXTRACT, START, END, X)
#define zero_extend(EXT, X)	BV_EXPRS(BCF_ZERO_EXTEND, EXT, X)
#define sign_extend(EXT, X)	BV_EXPRS(BCF_SIGN_EXTEND, EXT, X)
#define concat(...)		BV_EXPRS(BCF_CONCAT, __VA_ARGS__)
#define bvsize(X)		BV_EXPRS(BCF_BVSIZE, X)
#define from_bool(...)		BV_EXPRS(BCF_FROM_BOOL, __VA_ARGS__)
#define repeat(X, N)		BV_EXPRS(BCF_REPEAT, X, N)

#define VAL_TO_STRUCT(v)	{(u8)(v), (u8)((v) >> 8), (u16)((v) >> 16)}
#define bv_val(sz, ...)	\
	 ( EXPR1((BCF_BV | BCF_VAL), COUNT_ARGS(__VA_ARGS__), ENCODE_PARAM_LOW((sz))), \
	   __FOR_EACH(VAL_TO_STRUCT, __VA_ARGS__) )

static inline bool is_rw_bv_val(const struct bcf_expr_nullary *e)
{
	return e->code == (BCF_BV | BCF_VAL) && e->vlen && !BCF_PARAM_HIGH(e->params);
}

static inline u32 rw_bv_val(const struct bcf_expr_nullary *e)
{
	return (u32)e->code | (u32)e->vlen << 8 | (u32)e->params << 16;
}

/* For special bv constant encoding used in rewrites. */
#define CONST_BV_SYMBOLIC 1

#define bv_sym_val(val, sz)	\
	 BV_EXPR1S(BCF_VAL, ENCODE_PARAM_HIGH(CONST_BV_SYMBOLIC), val, sz)

static inline bool is_rw_sym_val(const struct bcf_expr_nullary *e)
{
	return e->code == (BCF_BV | BCF_VAL) && e->vlen == 2 &&
	       e->params == ENCODE_PARAM_HIGH(CONST_BV_SYMBOLIC);
}

#define bvmax(X)	\
	 BV_EXPR1S(BCF_VAL, ENCODE_PARAM_HIGH(CONST_BV_SYMBOLIC), X)

static inline bool is_rw_bvmax(const struct bcf_expr_nullary *e)
{
	return e->code == (BCF_BV | BCF_VAL) && e->vlen == 1 &&
	       e->params == ENCODE_PARAM_HIGH(CONST_BV_SYMBOLIC);
}

#define __ARR_NAME(_name, _suf)	__bcf_rw_##_name##_##_suf

// clang-format on
#define __MAKE_REWRITE(_name, _params_tuple, _match_tuple, _target_tuple,  \
		       _cond_expr, _cond_len)                              \
	static const struct bcf_expr_nullary __ARR_NAME(                   \
		_name, params)[] = { __UNTUPLE _params_tuple };            \
	static_assert(ARRAY_SIZE(__ARR_NAME(_name, params)) <= U8_MAX);    \
	static const struct bcf_expr_nullary __ARR_NAME(                   \
		_name, match)[] = { __UNTUPLE _match_tuple };              \
	static_assert(ARRAY_SIZE(__ARR_NAME(_name, match)) <= U8_MAX);     \
	static const struct bcf_expr_nullary __ARR_NAME(                   \
		_name, target)[] = { __UNTUPLE _target_tuple };            \
	static_assert(ARRAY_SIZE(__ARR_NAME(_name, target)) <= U8_MAX);    \
                                                                           \
	static const struct bcf_rewrite BCF_REWRITE_STRUCT_NAME(_name) = { \
		.name = #_name,                                            \
		.param_cnt = (u8)ARRAY_SIZE(__ARR_NAME(_name, params)),    \
		.params = __ARR_NAME(_name, params),                       \
		.match = __ARR_NAME(_name, match),                         \
		.match_len = (u8)ARRAY_SIZE(__ARR_NAME(_name, match)),     \
		.target = __ARR_NAME(_name, target),                       \
		.target_len = (u8)ARRAY_SIZE(__ARR_NAME(_name, target)),   \
		.cond = (_cond_expr),                                      \
		.cond_len = (_cond_len),                                   \
		.id = BCF_REWRITE_##_name,                                 \
	}

#define REWRITE(_name, _params_tuple, _match_tuple, _target_tuple)        \
	__MAKE_REWRITE(_name, _params_tuple, _match_tuple, _target_tuple, \
		       NULL, 0)

#define REWRITE_COND(_name, _params_tuple, _cond_tuple, _match_tuple,     \
		     _target_tuple)                                       \
	static const struct bcf_expr_nullary __ARR_NAME(                  \
		_name, cond)[] = { __UNTUPLE _cond_tuple };               \
	static_assert(ARRAY_SIZE(__ARR_NAME(_name, cond)) <= U8_MAX);     \
	__MAKE_REWRITE(_name, _params_tuple, _match_tuple, _target_tuple, \
		       __ARR_NAME(_name, cond),                           \
		       (u16)ARRAY_SIZE(__ARR_NAME(_name, cond)))

#endif /* __LINUX_BCF_REWRITE_DSL_H__ */
