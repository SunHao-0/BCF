// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kernel.h>
#include <linux/overflow.h>
#include <linux/errno.h>
#include <linux/export.h>
#include <linux/cleanup.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/xarray.h>
#include <linux/refcount.h>
#include <linux/bitmap.h>
#include <linux/sched/signal.h>
#include <linux/sched.h>
#include <linux/bcf_checker.h>

/* Per proof step state. */
struct bcf_step_state {
	/* The conclusion of the current step. */
	struct bcf_expr *fact;
	u32 fact_id;
	/* The last step referring to the current step. After `last_ref`, the
	 * `fact` is no longer used by any other steps and can be freed.
	 */
	u32 last_ref;
};

/* The expr buffer `exprs` below as well as `steps` rely on the fact that the
 * size of each arg is the same as the size of the struct bcf_expr, and no
 * padings in between and after.
 */
static_assert(sizeof(struct bcf_expr) ==
	      sizeof_field(struct bcf_expr, args[0]));
static_assert(sizeof(struct bcf_proof_step) ==
	      sizeof_field(struct bcf_proof_step, args[0]));

/* Size of expr/step in u32 plus the node itself */
#define EXPR_SZ(expr) ((expr)->vlen + 1)
#define STEP_SZ(step) ((step)->premise_cnt + (step)->param_cnt + 1)

#define bcf_for_each_arg(arg_id, expr)                                   \
	for (u32 ___i = 0, arg_id;                                       \
	     ___i < (expr)->vlen && (arg_id = (expr)->args[___i], true); \
	     ___i++)

#define bcf_for_each_expr(arg_expr, expr, st)                                  \
	for (u32 ___i = 0, ___id;                                              \
	     ___i < (expr)->vlen && (___id = (expr)->args[___i],               \
				    arg_expr = id_to_expr((st), ___id), true); \
	     ___i++)

/* Note: the defined iter variable is arg_i, not arg_id. */
#define bcf_for_each_arg_expr(arg_i, arg_expr, expr, st)                      \
	for (u32 arg_i = 0, ___id; arg_i < (expr)->vlen &&                    \
				   (___id = (expr)->args[arg_i],              \
				   arg_expr = id_to_expr((st), ___id), true); \
	     arg_i++)

#define bcf_for_each_pm_step(step_id, step)                               \
	for (u32 ___i = 0, step_id; ___i < (step)->premise_cnt &&         \
				    (step_id = (step)->args[___i], true); \
	     ___i++)

#define bcf_for_each_pm_expr(pm, step, st)                  \
	for (u32 ___i = 0, ___step_id;                      \
	     ___i < (step)->premise_cnt &&                  \
	     (___step_id = (step)->args[___i],              \
	     pm = (st)->step_state[___step_id].fact, true); \
	     ___i++)

#define bcf_for_each_pm_id(pm_id, step, st)                       \
	for (u32 ___i = 0, ___step_id, pm_id;                     \
	     ___i < (step)->premise_cnt &&                        \
	     (___step_id = (step)->args[___i],                    \
	     pm_id = (st)->step_state[___step_id].fact_id, true); \
	     ___i++)

/* For expr equivalence comparison, see __expr_equiv(). */
#define BCF_MAX_CMP_STACK 128
struct bcf_cmp_stack_elem {
	struct bcf_expr *e0, *e1;
	u32 cur_arg;
};

#define __MAX_BCF_STACK (sizeof(struct bcf_cmp_stack_elem) * BCF_MAX_CMP_STACK)

/* For constant expr evaluation, see eval_const_expr(). */
#define BCF_MAX_EVAL_STACK \
	(__MAX_BCF_STACK / sizeof(struct bcf_eval_stack_elem))
struct bcf_eval_stack_elem {
	struct bcf_expr *expr;
	union {
		u32 cur_arg;
		u64 bv_res;
		bool bool_res;
	};
};

/* Fixed-size expr for common cases */
struct bcf_expr_unary {
	u8 code;
	u8 vlen;
	u16 params;
	u32 arg0;
};
static_assert(sizeof(struct bcf_expr_unary) ==
	      struct_size_t(struct bcf_expr, args, 1));

struct bcf_expr_buf {
	u8 code;
	u8 vlen;
	u16 params;
	u32 args[U8_MAX];
};
static_assert(sizeof(struct bcf_expr_buf) ==
	      struct_size_t(struct bcf_expr, args, U8_MAX));

struct bcf_checker_state {
	/* Exprs from the proof, referred to as `static expr`. They exist
	 * during the entire checking phase.
	 */
	struct bcf_expr *exprs;
	/* Each expr of `exprs` is followed by their arguments. The `valid_idx`
	 * bitmap records the valid indices of exprs.
	 */
	unsigned long *valid_idx;
	/* Size of exprs array. */
	u32 expr_size;
	/* For exprs that are allocated dynamically during proof checking, e.g.,
	 * conclusions from proof steps, they are refcounted, and each allocated
	 * expr has an id (increased after `expr_size`) and is stored in xarray.
	 *
	 * With this xarray, any routines below can exit early on any error
	 * without worrying about freeing the exprs allocated; they can be
	 * freed once when freeing the xarray, see free_checker_state().
	 */
	u32 id_gen;
	struct xarray expr_id_map; /* Id (u32) to `struct bcf_expr_ref` */

	/* Step state tracking */
	struct bcf_proof_step *steps;
	struct bcf_step_state *step_state;
	u32 step_size; /* size of steps array */
	u32 step_cnt; /* valid number of steps */
	u32 cur_step;
	u32 cur_step_idx;

	bcf_logger_t logger;
	void *logger_private;
	u32 level;

	u32 goal;
	struct bcf_expr *goal_exprs;

	/* Builtin expr id. */
	u32 true_expr;
	u32 false_expr;

	/* Pre-allocated expr bufs used by different routines. */
	struct bcf_expr_buf expr_buf;
	struct bcf_expr_unary not_expr; /* Used by resolution. */

	/* Shared stack space: used either by equivalence comparison or by
	 * constant evaluation, *exclusively*.
	 */
	union {
		struct bcf_cmp_stack_elem cmp[BCF_MAX_CMP_STACK];
		struct bcf_eval_stack_elem eval[BCF_MAX_EVAL_STACK];
	} stack;
};

static void free_checker_state(struct bcf_checker_state *st)
{
	unsigned long id;
	void *expr;

	kvfree(st->exprs);
	kvfree(st->valid_idx);
	xa_for_each(&st->expr_id_map, id, expr) {
		kfree(expr);
	}
	xa_destroy(&st->expr_id_map);
	kvfree(st->steps);
	kvfree(st->step_state);

	kfree(st);
}
DEFINE_FREE(free_checker, struct bcf_checker_state *,
	    if (_T) free_checker_state(_T))

__printf(2, 3) static void verbose(struct bcf_checker_state *st,
				   const char *fmt, ...)
{
	va_list args;

	if (!st->logger || !st->level)
		return;
	va_start(args, fmt);
	st->logger(st->logger_private, fmt, args);
	va_end(args);
}

/* Ref-counted bcf_expr */
struct bcf_expr_ref {
	union {
		struct {
			refcount_t refcnt;
			u32 id;
		};
		/* When the refcnt is zero, its id and the counter are not used
		 * anymore, so reuse the space for free list, see expr_put()
		 */
		struct bcf_expr_ref *free_next;
	};
	union {
		/* Identical to struct bcf_expr, access helper. */
		struct {
			u8 code;
			u8 vlen;
			u16 params;
			u32 args[];
		};
		struct bcf_expr expr;
	};
};
static_assert(offsetof(struct bcf_expr_ref, code) ==
	      offsetof(struct bcf_expr_ref, expr.code));

/* Every expr has an id: (1) for static exprs, the idx to `exprs` is its id;
 * (2) dynamically-allocated ones get one from st->id_gen++.
 */
static bool is_static_expr_id(struct bcf_checker_state *st, u32 id)
{
	return id < st->expr_size;
}

static bool expr_arg_is_id(u8 code)
{
	/* Each arg of a bcf_expr must be an id, except for bv_val, which is a
	 * sequence of u32 values.
	 */
	return code != (BCF_BV | BCF_VAL);
}

/* Use eref to refer to a ref-counted expr. */
static void expr_id_get(struct bcf_checker_state *st, u32 id)
{
	struct bcf_expr_ref *eref;

	if (is_static_expr_id(st, id))
		return;
	eref = xa_load(&st->expr_id_map, id);
	refcount_inc(&eref->refcnt);
}

static void __push_free(struct bcf_checker_state *st,
			struct bcf_expr_ref **head, struct bcf_expr_ref *eref)
{
	/* Never free builtin exprs. */
	if (eref->id == st->true_expr || eref->id == st->false_expr)
		return;

	if (refcount_dec_and_test(&eref->refcnt)) {
		xa_erase(&st->expr_id_map, eref->id);
		eref->free_next = *head;
		*head = eref;
	}
}

static void expr_put(struct bcf_checker_state *st, struct bcf_expr *expr)
{
	struct bcf_expr_ref *free_head = NULL;
	struct bcf_expr_ref *eref;

	if (expr >= st->exprs && expr < st->exprs + st->expr_size)
		return;

	eref = container_of(expr, struct bcf_expr_ref, expr);
	__push_free(st, &free_head, eref);

	while (free_head) {
		eref = free_head;
		free_head = free_head->free_next;

		bcf_for_each_arg(arg_id, &eref->expr) {
			if (!expr_arg_is_id(eref->code))
				break;

			if (is_static_expr_id(st, arg_id))
				continue;

			__push_free(st, &free_head,
				    xa_load(&st->expr_id_map, arg_id));
		}
		kfree(eref);
	}
}

/* REQUIRES: id must be valid, i.e., either a static id or from id_gen.
 * ENSURES: returned ptr is non-null.
 */
static struct bcf_expr *id_to_expr(struct bcf_checker_state *st, u32 id)
{
	struct bcf_expr_ref *eref;

	if (is_static_expr_id(st, id))
		return st->exprs + id;

	eref = xa_load(&st->expr_id_map, id);
	return &eref->expr;
}

static void expr_id_put(struct bcf_checker_state *st, u32 id)
{
	expr_put(st, id_to_expr(st, id));
}

static struct bcf_expr_ref *alloc_expr(struct bcf_checker_state *st, u8 vlen)
{
	struct bcf_expr_ref *eref;
	void *entry;

	eref = kmalloc(struct_size(eref, expr.args, vlen), GFP_KERNEL);
	if (!eref)
		return ERR_PTR(-ENOMEM);
	eref->id = st->id_gen++;
	entry = xa_store(&st->expr_id_map, eref->id, eref, GFP_KERNEL);
	if (xa_is_err(entry)) {
		kfree(eref);
		return ERR_PTR(xa_err(entry));
	}

	/* The caller owns the expr. */
	refcount_set(&eref->refcnt, 1);
	return eref;
}

static struct bcf_expr_ref *new_expr(struct bcf_checker_state *st, bool move,
				     u8 code, u16 params, u32 vlen, ...)
{
	struct bcf_expr_ref *eref;
	va_list args;

	if (WARN_ON_ONCE(vlen > U8_MAX))
		return ERR_PTR(-EFAULT);

	eref = alloc_expr(st, vlen);
	if (IS_ERR(eref))
		return eref;
	eref->code = code;
	eref->vlen = vlen;
	eref->params = params;

	va_start(args, vlen);
	for (u32 i = 0; i < vlen; i++) {
		u32 arg = va_arg(args, u32);

		if (!move && expr_arg_is_id(code))
			expr_id_get(st, arg);
		eref->args[i] = arg;
	}
	va_end(args);

	return eref;
}

/* Create a new expr with args ref increased. */
#define build_expr(st, code, params, ...) \
	new_expr(st, false, code, params, COUNT_ARGS(__VA_ARGS__), __VA_ARGS__)
/* Create a new expr *without* increasing arg ref, i.e., move the ownership of
 * the args to the current expr.
 */
#define build_expr_move(st, code, params, ...) \
	new_expr(st, true, code, params, COUNT_ARGS(__VA_ARGS__), __VA_ARGS__)

static struct bcf_expr_ref *clone_expr(struct bcf_checker_state *st,
				       struct bcf_expr *expr)
{
	struct bcf_expr_ref *eref;

	eref = alloc_expr(st, expr->vlen);
	if (IS_ERR(eref))
		return eref;
	eref->expr = *expr;

	for (u32 i = 0; i < expr->vlen; i++) {
		if (expr_arg_is_id(expr->code))
			expr_id_get(st, expr->args[i]);
		eref->args[i] = expr->args[i];
	}

	return eref;
}

static struct bcf_expr *realloc_expr(struct bcf_checker_state *st, u32 expr_id,
				     u32 new_vlen)
{
	struct bcf_expr_ref *eref;

	eref = xa_load(&st->expr_id_map, expr_id);
	if (WARN_ON_ONCE(!eref))
		return ERR_PTR(-EFAULT);

	eref = krealloc(eref, struct_size(eref, expr.args, new_vlen),
			GFP_KERNEL);
	if (!eref)
		/* eref freed during free_checker_state() */
		return ERR_PTR(-ENOMEM);

	BUG_ON(xa_is_err(
		xa_store(&st->expr_id_map, expr_id, eref, GFP_KERNEL)));
	return &eref->expr;
}

static int __copy_expr_args(struct bcf_expr *dst, struct bcf_expr *src,
			    bool append)
{
	u32 *args = dst->args;

	if (append) {
		args += dst->vlen;
		if ((u32)dst->vlen + src->vlen > U8_MAX)
			return -E2BIG;
		dst->vlen += src->vlen;
	} else {
		dst->vlen = src->vlen;
	}
	memcpy(args, src->args, sizeof(u32) * src->vlen);
	return 0;
}

/* Append args from src to dst, and update vlen */
static int append_expr_args(struct bcf_expr *dst, struct bcf_expr *src)
{
	return __copy_expr_args(dst, src, true);
}

/* Copy args from src to dst, and set vlen */
static int copy_expr_args(struct bcf_expr *dst, struct bcf_expr *src)
{
	return __copy_expr_args(dst, src, false);
}

static void remove_expr_arg(struct bcf_checker_state *st, struct bcf_expr *expr,
			    u32 i, bool own_args)
{
	u32 rest;

	if (own_args && expr_arg_is_id(expr->code))
		expr_id_put(st, expr->args[i]);

	rest = expr->vlen - (i + 1);
	if (rest)
		memmove(&expr->args[i], &expr->args[i + 1], sizeof(u32) * rest);
	expr->vlen--;
}

/* type/operation/arity table */
#define Nullary { 0, 0 }
#define Unary { 1, 1 }
#define Binary { 2, 2 }
#define Ternary { 3, 3 }
#define Vari(l) { (l), U8_MAX }

#define BCF_BV_OP_NULLARY(FN) FN(BCF_BV, bv, BCF_VAR, var, Nullary)

#define BCF_BV_OP_UNARY(FN)                                 \
	FN(BCF_BV, bv, BPF_NEG, neg, Unary)                 \
	FN(BCF_BV, bv, BCF_EXTRACT, extract, Unary)         \
	FN(BCF_BV, bv, BCF_SIGN_EXTEND, sign_extend, Unary) \
	FN(BCF_BV, bv, BCF_ZERO_EXTEND, zero_extend, Unary) \
	FN(BCF_BV, bv, BCF_BVSIZE, bvsize, Unary)           \
	FN(BCF_BV, bv, BCF_REPEAT, repeat, Unary)           \
	FN(BCF_BV, bv, BCF_BVNOT, not, Unary)

#define BCF_BV_OP_BINARY(FN)                   \
	FN(BCF_BV, bv, BPF_SUB, sub, Binary)   \
	FN(BCF_BV, bv, BPF_LSH, lsh, Binary)   \
	FN(BCF_BV, bv, BPF_RSH, rsh, Binary)   \
	FN(BCF_BV, bv, BPF_ARSH, arsh, Binary) \
	FN(BCF_BV, bv, BPF_DIV, div, Binary)   \
	FN(BCF_BV, bv, BPF_MOD, mod, Binary)   \
	FN(BCF_BV, bv, BCF_SDIV, sdiv, Binary) \
	FN(BCF_BV, bv, BCF_SMOD, smod, Binary)

#define BCF_BV_OP_TERNARY(FN) FN(BCF_BV, bv, BCF_ITE, ite, Ternary)

#define BCF_BV_OP_VARIADIC(FN)                \
	FN(BCF_BV, bv, BPF_ADD, add, Vari(2)) \
	FN(BCF_BV, bv, BPF_MUL, mul, Vari(2)) \
	FN(BCF_BV, bv, BPF_OR, or, Vari(2))   \
	FN(BCF_BV, bv, BPF_AND, and, Vari(2)) \
	FN(BCF_BV, bv, BPF_XOR, xor, Vari(2)) \
	FN(BCF_BV, bv, BCF_CONCAT, concat, Vari(2))

#define BCF_BV_OP_VAL_VARIADIC(FN)            \
	FN(BCF_BV, bv, BCF_VAL, val, Vari(1)) \
	FN(BCF_BV, bv, BCF_FROM_BOOL, from_bool, Vari(1))

#define BCF_BV_OP(FN)          \
	BCF_BV_OP_NULLARY(FN)  \
	BCF_BV_OP_UNARY(FN)    \
	BCF_BV_OP_BINARY(FN)   \
	BCF_BV_OP_TERNARY(FN)  \
	BCF_BV_OP_VARIADIC(FN) \
	BCF_BV_OP_VAL_VARIADIC(FN)

#define BCF_BOOL_OP_NULLARY(FN)                   \
	FN(BCF_BOOL, bool, BCF_VAL, val, Nullary) \
	FN(BCF_BOOL, bool, BCF_VAR, var, Nullary)

#define BCF_BOOL_OP_UNARY(FN)                   \
	FN(BCF_BOOL, bool, BCF_NOT, not, Unary) \
	FN(BCF_BOOL, bool, BCF_BITOF, bitof, Unary)

#define BCF_BOOL_OP_BINARY(FN)                        \
	FN(BCF_BOOL, bool, BPF_JEQ, eq, Binary)       \
	FN(BCF_BOOL, bool, BPF_JNE, distinct, Binary) \
	FN(BCF_BOOL, bool, BPF_JGT, ugt, Binary)      \
	FN(BCF_BOOL, bool, BPF_JGE, uge, Binary)      \
	FN(BCF_BOOL, bool, BPF_JSGT, sgt, Binary)     \
	FN(BCF_BOOL, bool, BPF_JSGE, sge, Binary)     \
	FN(BCF_BOOL, bool, BPF_JLT, ult, Binary)      \
	FN(BCF_BOOL, bool, BPF_JLE, ule, Binary)      \
	FN(BCF_BOOL, bool, BPF_JSLT, slt, Binary)     \
	FN(BCF_BOOL, bool, BPF_JSLE, sle, Binary)     \
	FN(BCF_BOOL, bool, BCF_IMPLIES, implies, Binary)

#define BCF_BOOL_OP_TERNARY(FN) FN(BCF_BOOL, bool, BCF_ITE, ite, Ternary)

#define BCF_BOOL_OP_VARIADIC(FN)                    \
	FN(BCF_BOOL, bool, BCF_CONJ, conj, Vari(2)) \
	FN(BCF_BOOL, bool, BCF_DISJ, disj, Vari(2)) \
	FN(BCF_BOOL, bool, BCF_XOR, xor, Vari(2))

#define BCF_BOOL_OP(FN)         \
	BCF_BOOL_OP_NULLARY(FN) \
	BCF_BOOL_OP_UNARY(FN)   \
	BCF_BOOL_OP_BINARY(FN)  \
	BCF_BOOL_OP_TERNARY(FN) \
	BCF_BOOL_OP_VARIADIC(FN)

#define BCF_LIST_OP(FN) FN(BCF_LIST, list, BCF_VAL, val, Vari(0))

#define BCF_OP_TABLE(FN) \
	BCF_BV_OP(FN)    \
	BCF_BOOL_OP(FN)  \
	BCF_LIST_OP(FN)

static bool in_codetable(u8 code)
{
#define CODE_TBL(ty, _t, op, _o, _arity) [ty | op] = true,
	static const bool codetable[256] = { [0 ... 255] = false,
					     BCF_OP_TABLE(CODE_TBL) };
#undef CODE_TBL
	return codetable[code];
}

static const char *code_str(u8 code)
{
#define CODE_TBL(ty, ty_name, op, op_name, _arity) \
	[ty | op] = __stringify(ty_name##_##op_name),
	static const char *strtable[256] = { [0 ... 255] = "unknown",
					     BCF_OP_TABLE(CODE_TBL) };
#undef CODE_TBL
	return strtable[code];
}

/* Variadic operators that reduce to their single argument when given only one operand.
 * For example, (xor bv0) is equivalent to bv0. This property is used in rule applications.
 */
static bool reducible_variadic(u8 code)
{
#define CODE_TBL(ty, _ty_name, op, _op_name, _arity) [ty | op] = true,
	static const bool reducible[256] = {
		[0 ... 255] = false,
		BCF_BV_OP_VARIADIC(CODE_TBL) BCF_BOOL_OP_VARIADIC(CODE_TBL)
	};
#undef CODE_TBL
	return reducible[code];
}

static bool valid_arity(u8 code, u8 vlen)
{
#define ARITY_TBL(ty, _t, op, _o, arity) [ty | op] = arity,
	static const struct bcf_arity {
		u8 min, max;
	} arity[256] = { [0 ... 255] = Nullary, BCF_OP_TABLE(ARITY_TBL) };
#undef ARITY_TBL
	return vlen >= arity[code].min && vlen <= arity[code].max;
}

/* Define code checks, e.g., is_bool_eq(u8 code). */
#define DEFINE_CODE_CHECK(ty, ty_name, op, op_name, _arity) \
	static bool is_##ty_name##_##op_name(u8 code)       \
	{                                                   \
		return code == ((ty) | (op));               \
	}

#define BCF_ARGS_DECL_Nullary
#define BCF_ARGS_DECL_Unary , u32 e0
#define BCF_ARGS_DECL_Binary , u32 e0, u32 e1
#define BCF_ARGS_DECL_Ternary , u32 e0, u32 e1, u32 e2

#define BCF_ARGS_PASS_Nullary
#define BCF_ARGS_PASS_Unary , e0
#define BCF_ARGS_PASS_Binary , e0, e1
#define BCF_ARGS_PASS_Ternary , e0, e1, e2

/* Define build rountines for ops with fixed arity, e.g., build_bool_eq(st, e0, e1). */
#define DEFINE_EXPR_BUILD(ty, ty_name, op, op_name, arity)              \
	static struct bcf_expr_ref *build_##ty_name##_##op_name(        \
		struct bcf_checker_state *st BCF_ARGS_DECL_##arity)     \
	{                                                               \
		u32 _arity[] = arity;                                   \
		return new_expr(st, false, (ty) | (op), 0,              \
				_arity[0] BCF_ARGS_PASS_##arity);       \
	}                                                               \
	static struct bcf_expr_ref *build_##ty_name##_##op_name##_move( \
		struct bcf_checker_state *st BCF_ARGS_DECL_##arity)     \
	{                                                               \
		u32 _arity[] = arity;                                   \
		return new_expr(st, true, (ty) | (op), 0,               \
				_arity[0] BCF_ARGS_PASS_##arity);       \
	}

#define DEFINE_OPERAND_CHECK_BINARY(_ty, ty_name, _op, op_name, _arity)     \
	static bool is_##ty_name##_##op_name##_of(                          \
		struct bcf_checker_state *st, u32 id, u32 arg0, u32 arg1)   \
	{                                                                   \
		struct bcf_expr *e = id_to_expr(st, id);                    \
		return is_##ty_name##_##op_name(e->code) && e->vlen == 2 && \
		       e->args[0] == arg0 && e->args[1] == arg1;            \
	}

__diag_push();
__diag_ignore_all("-Wunused-function",
		  "Allow unused functions for macro-defined functions");
BCF_OP_TABLE(DEFINE_CODE_CHECK)

BCF_BV_OP_NULLARY(DEFINE_EXPR_BUILD)
BCF_BOOL_OP_NULLARY(DEFINE_EXPR_BUILD)
BCF_BV_OP_UNARY(DEFINE_EXPR_BUILD)
BCF_BOOL_OP_UNARY(DEFINE_EXPR_BUILD)
BCF_BV_OP_BINARY(DEFINE_EXPR_BUILD)
BCF_BOOL_OP_BINARY(DEFINE_EXPR_BUILD)
BCF_BV_OP_TERNARY(DEFINE_EXPR_BUILD)
BCF_BOOL_OP_TERNARY(DEFINE_EXPR_BUILD)

BCF_BV_OP_BINARY(DEFINE_OPERAND_CHECK_BINARY)
BCF_BOOL_OP_BINARY(DEFINE_OPERAND_CHECK_BINARY)
__diag_pop();

static bool is_bool(u8 code)
{
	return BCF_TYPE(code) == BCF_BOOL;
}

static bool is_bv(u8 code)
{
	return BCF_TYPE(code) == BCF_BV;
}

static bool is_list(u8 code)
{
	return BCF_TYPE(code) == BCF_LIST;
}

static bool is_val(u8 code)
{
	return BCF_OP(code) == BCF_VAL;
}

static bool is_var(u8 code)
{
	return BCF_OP(code) == BCF_VAR;
}

static bool is_ite(u8 code)
{
	return BCF_OP(code) == BCF_ITE;
}

static bool is_true(const struct bcf_expr *expr)
{
	return is_bool_val(expr->code) &&
	       BCF_BOOL_LITERAL(expr->params) == BCF_TRUE;
}

static bool is_false(const struct bcf_expr *expr)
{
	return is_bool_val(expr->code) &&
	       BCF_BOOL_LITERAL(expr->params) == BCF_FALSE;
}

static bool is_ite_bool_cond(struct bcf_checker_state *st, struct bcf_expr *e)
{
	if (is_ite(e->code)) {
		if (is_bv_ite(e->code))
			return is_bool(id_to_expr(st, e->args[0])->code);
		return true;
	}
	return false;
}

static bool is_bool_xor_of(struct bcf_checker_state *st, u32 id, u32 a, u32 b)
{
	struct bcf_expr *e = id_to_expr(st, id);

	return e->code == (BCF_BOOL | BCF_XOR) && e->vlen == 2 &&
	       e->args[0] == a && e->args[1] == b;
}

static bool is_bool_disj_of(struct bcf_checker_state *st, u32 id, u32 a, u32 b)
{
	struct bcf_expr *e = id_to_expr(st, id);

	return e->code == (BCF_BOOL | BCF_DISJ) && e->vlen == 2 &&
	       e->args[0] == a && e->args[1] == b;
}

static bool is_bitof(struct bcf_checker_state *st, u32 id, u32 bit, u32 bv_id)
{
	struct bcf_expr *e = id_to_expr(st, id);

	return e->code == (BCF_BOOL | BCF_BITOF) && e->args[0] == bv_id &&
	       BCF_BITOF_BIT(e->params) == bit;
}

static bool is_bool_not_of(struct bcf_checker_state *st, u32 not_id, u32 e_id)
{
	struct bcf_expr *not_expr = id_to_expr(st, not_id);

	return is_bool_not(not_expr->code) && not_expr->args[0] == e_id;
}

#define build_disj(st, ...) build_expr(st, BCF_BOOL | BCF_DISJ, 0, __VA_ARGS__)
#define build_disj_move(st, ...) \
	build_expr_move(st, BCF_BOOL | BCF_DISJ, 0, __VA_ARGS__)

static struct bcf_expr_ref *build_bv_val(struct bcf_checker_state *st, u8 bv_sz,
					 u64 val)
{
	if (bv_sz <= 32)
		return build_expr_move(st, BCF_BV | BCF_VAL, bv_sz, (u32)val);
	else
		return build_expr_move(st, BCF_BV | BCF_VAL, bv_sz, (u32)val,
				       (u32)(val >> 32));
}

static const struct bcf_expr bcf_bool_false = {
	.code = BCF_BOOL | BCF_VAL,
	.vlen = 0,
	.params = BCF_FALSE,
};

static const struct bcf_expr bcf_bool_true = {
	.code = BCF_BOOL | BCF_VAL,
	.vlen = 0,
	.params = BCF_TRUE,
};

/* Exprs referred to by the proof steps are static exprs from the proof.
 * Hence, must be valid id in st->exprs.
 */
static bool valid_arg_id(struct bcf_checker_state *st, u32 id)
{
	return is_static_expr_id(st, id) && test_bit(id, st->valid_idx);
}

static struct bcf_expr *get_arg_expr(struct bcf_checker_state *st, u32 id)
{
	return valid_arg_id(st, id) ? st->exprs + id : ERR_PTR(-EINVAL);
}

static struct bcf_expr *get_bool_arg(struct bcf_checker_state *st, u32 id)
{
	struct bcf_expr *e = get_arg_expr(st, id);

	if (IS_ERR(e))
		return e;
	return is_bool(e->code) ? e : ERR_PTR(-EINVAL);
}

static u8 bv_size(struct bcf_expr *expr)
{
	if (BCF_OP(expr->code) == BCF_EXTRACT)
		return BCF_EXTRACT_START(expr->params) -
		       BCF_EXTRACT_END(expr->params) + 1;

	if (BCF_OP(expr->code) == BCF_FROM_BOOL)
		return expr->vlen;

	return BCF_BV_WIDTH(expr->params);
}

static u8 bv_val_vlen(u8 sz)
{
	return DIV_ROUND_UP_POW2(sz, 32);
}

static u64 bv_val(struct bcf_expr *bv)
{
	u64 val = bv->args[0];

	if (bv->vlen > 1) {
		WARN_ON_ONCE(bv->vlen != 2);
		val |= ((u64)bv->args[1] << 32);
	}
	return val;
}

static u64 bv_max(u8 bw)
{
	WARN_ON_ONCE(bw > 64);
	return GENMASK_ULL(bw - 1, 0);
}

static bool same_type(struct bcf_expr *e0, struct bcf_expr *e1)
{
	u8 ty0 = BCF_TYPE(e0->code), ty1 = BCF_TYPE(e1->code);

	if (ty0 != ty1)
		return false;
	if (ty0 == BCF_BV)
		return bv_size(e0) == bv_size(e1);
	else if (ty0 == BCF_LIST)
		return e0->vlen == e1->vlen && e0->params == e1->params;
	return true;
}

/* Rather than using:
 *	if (!correct_condition0 or !correct_condition1)
 *		return err;
 * the `ENSURE` macro make this more readable:
 *	ENSURE(c0 && c1);
 */
#define ENSURE(cond)                    \
	do {                            \
		if (!(cond))            \
			return -EINVAL; \
	} while (0)

/* Use ERR_PTR for pointer errors, never NULL, so IS_ERR checks work reliably.
 * CHECK_PTR macro simplifies error handling by propagating errors immediately,
 * e.g., for -ENOMEM.
 */
#define CHECK_PTR(ptr)                         \
	do {                                   \
		if (IS_ERR((ptr)))             \
			return PTR_ERR((ptr)); \
	} while (0)

static int type_check_bv(struct bcf_checker_state *st, struct bcf_expr *expr)
{
	struct bcf_expr *arg = NULL;
	u8 op = BCF_OP(expr->code);
	u32 bv_sz;

	bv_sz = bv_size(expr);
	ENSURE(bv_sz); /* must not be bv(0) */

	if (op == BCF_ITE) {
		ENSURE(!BCF_PARAM_HIGH(expr->params));
		bcf_for_each_arg_expr(i, arg, expr, st) {
			if (i == 0)
				ENSURE(is_bool(arg->code) ||
				       (is_bv(arg->code) && bv_size(arg) == 1));
			else
				ENSURE(same_type(expr, arg));
		}
		return 0;
	} else if (op == BCF_FROM_BOOL) {
		bcf_for_each_expr(arg, expr, st)
			ENSURE(is_bool(arg->code));
		ENSURE(!expr->params); /* reserved */
		return 0;
	}

	if (expr->vlen && expr_arg_is_id(expr->code)) {
		arg = id_to_expr(st, expr->args[0]);
		ENSURE(is_bv(arg->code));
	}

	/* Check indexed operators */
	if (op == BCF_EXTRACT) {
		u32 start = BCF_EXTRACT_START(expr->params);
		u32 end = BCF_EXTRACT_END(expr->params);
		/* Must extract a bv expr with a valid range. */
		ENSURE(start >= end && bv_size(arg) > start);
		return 0;
	} else if (op == BCF_ZERO_EXTEND || op == BCF_SIGN_EXTEND) {
		u32 ext_sz = BCF_EXT_LEN(expr->params);

		ENSURE(bv_size(arg) + ext_sz == bv_sz);
		return 0;
	} else if (op == BCF_REPEAT) {
		u32 repeat_size = BCF_REPEAT_N(expr->params);

		repeat_size *= bv_size(arg);
		ENSURE(repeat_size == bv_sz);
		return 0;
	}

	/* For the rest, param_high is preserved */
	ENSURE(!BCF_PARAM_HIGH(expr->params));

	switch (op) {
	case BCF_VAL: {
		u32 vlen = bv_val_vlen(bv_sz);
		u64 mask;

		/* restrict bv val to be smaller then 64 bits */
		ENSURE(expr->vlen <= 2 && vlen == expr->vlen);
		mask = bv_max(bv_sz);
		ENSURE((~mask & bv_val(expr)) == 0);
		break;
	}
	case BCF_CONCAT: {
		u64 arg_sz = 0;

		bcf_for_each_expr(arg, expr, st) {
			ENSURE(is_bv(arg->code));
			arg_sz += bv_size(arg);
		}
		ENSURE(arg_sz == bv_sz);
		break;
	}
	case BCF_BVSIZE:
		ENSURE(bv_size(arg) <= bv_max(bv_sz));
		break;
	default:
		/* For all other operators, ensure type matches */
		bcf_for_each_expr(arg, expr, st)
			ENSURE(same_type(expr, arg));
		break;
	}

	return 0;
}

static int type_check_bool(struct bcf_checker_state *st, struct bcf_expr *expr)
{
	struct bcf_expr *arg0 = NULL, *arg1 = NULL;
	u8 op = BCF_OP(expr->code);

	if (op == BCF_BITOF) {
		u8 bit = BCF_BITOF_BIT(expr->params);

		ENSURE(!BCF_PARAM_HIGH(expr->params));
		arg0 = id_to_expr(st, expr->args[0]);
		ENSURE(is_bv(arg0->code) && bit < bv_size(arg0));
		return 0;
	} else if (op == BCF_VAL) {
		ENSURE((expr->params & ~1) == 0);
		return 0;
	}

	ENSURE(!expr->params); /* reserved */

	if (expr->vlen == 2) {
		arg0 = id_to_expr(st, expr->args[0]);
		arg1 = id_to_expr(st, expr->args[1]);
	}

	switch (op) {
	case BPF_JGT:
	case BPF_JGE:
	case BPF_JSGT:
	case BPF_JSGE:
	case BPF_JLT:
	case BPF_JLE:
	case BPF_JSLT:
	case BPF_JSLE: /* BV predicate */
		ENSURE(is_bv(arg0->code) && same_type(arg0, arg1));
		break;
	case BPF_JEQ:
	case BPF_JNE: /* bool or bv */
		ENSURE(!is_list(arg0->code) && same_type(arg0, arg1));
		break;
	default:
		/* For all other operators, ensure all args are bool */
		bcf_for_each_expr(arg0, expr, st)
			ENSURE(is_bool(arg0->code));
		break;
	}

	return 0;
}

static int type_check_list(struct bcf_checker_state *st, struct bcf_expr *expr)
{
	struct bcf_expr *arg;
	u8 elem_ty;

	ENSURE(!BCF_PARAM_HIGH(expr->params));
	elem_ty = BCF_PARAM_LOW(expr->params);
	ENSURE(elem_ty < __MAX_BCF_TYPE && elem_ty != BCF_LIST);
	bcf_for_each_expr(arg, expr, st)
		ENSURE(BCF_TYPE(arg->code) == elem_ty);

	return 0;
}

static int type_check(struct bcf_checker_state *st, struct bcf_expr *expr)
{
	ENSURE(in_codetable(expr->code));
	ENSURE(valid_arity(expr->code, expr->vlen));

	switch (BCF_TYPE(expr->code)) {
	case BCF_BV:
		return type_check_bv(st, expr);
	case BCF_BOOL:
		return type_check_bool(st, expr);
	case BCF_LIST:
		return type_check_list(st, expr);
	default:
		WARN_ONCE(1, "Unknown type: %u", BCF_TYPE(expr->code));
		return -EFAULT;
	}
}

static void record_builtins(struct bcf_checker_state *st, struct bcf_expr *expr,
			    u32 id)
{
	if (st->true_expr == U32_MAX && is_true(expr))
		st->true_expr = id;
	if (st->false_expr == U32_MAX && is_false(expr))
		st->false_expr = id;
}

static int alloc_builtins(struct bcf_checker_state *st)
{
	struct bcf_expr_ref *eref;

	if (st->true_expr == U32_MAX) {
		eref = build_bool_val(st);
		CHECK_PTR(eref);
		eref->params = BCF_TRUE;
		st->true_expr = eref->id;
	}
	if (st->false_expr == U32_MAX) {
		eref = build_bool_val(st);
		CHECK_PTR(eref);
		eref->params = BCF_FALSE;
		st->false_expr = eref->id;
	}
	return 0;
}

static int check_exprs(struct bcf_checker_state *st, bpfptr_t bcf_buf,
		       u32 expr_size)
{
	u32 idx = 0;
	int err;

	st->exprs =
		kvmemdup_bpfptr(bcf_buf, expr_size * sizeof(struct bcf_expr));
	if (IS_ERR(st->exprs)) {
		err = PTR_ERR(st->exprs);
		st->exprs = NULL;
		return err;
	}
	st->expr_size = expr_size;
	st->id_gen = expr_size;

	st->valid_idx = kvzalloc(bitmap_size(expr_size), GFP_KERNEL);
	if (!st->valid_idx) {
		kvfree(st->exprs);
		st->exprs = NULL;
		return -ENOMEM;
	}

	st->true_expr = U32_MAX;
	st->false_expr = U32_MAX;

	while (idx < expr_size) {
		struct bcf_expr *expr = st->exprs + idx;
		u32 expr_sz = EXPR_SZ(expr);

		ENSURE(idx + expr_sz <= expr_size);

		bcf_for_each_arg(arg_id, expr) {
			if (!expr_arg_is_id(expr->code))
				break;
			/* The bitmap enforces that each expr can refer only to
			 * valid, previous exprs.
			 */
			ENSURE(valid_arg_id(st, arg_id));
		}

		err = type_check(st, expr);
		if (err)
			return err;

		record_builtins(st, expr, idx);
		set_bit(idx, st->valid_idx);
		idx += expr_sz;
	}
	ENSURE(idx == expr_size);

	return alloc_builtins(st);
}

static bool is_leaf_node(struct bcf_expr *e)
{
	return !e->vlen || !expr_arg_is_id(e->code);
}

#define BCF_MAX_VAR_MAP 128
struct bcf_var_map {
	struct {
		u32 idx0;
		u32 idx1;
	} pair[BCF_MAX_VAR_MAP];
	u32 cnt;
};

static int var_equiv(struct bcf_var_map *map, u32 v0, u32 v1, bool from_checker)
{
	/* Variables from the checker must have the same id. */
	if (from_checker)
		return v0 == v1 ? 1 : 0;

	for (u32 i = 0; i < map->cnt; i++) {
		if (map->pair[i].idx0 == v0)
			return map->pair[i].idx1 == v1 ? 1 : 0;
		if (map->pair[i].idx1 == v1)
			return 0;
	}

	if (map->cnt < BCF_MAX_VAR_MAP) {
		map->pair[map->cnt].idx0 = v0;
		map->pair[map->cnt].idx1 = v1;
		map->cnt++;
		return 1;
	}

	return -E2BIG;
}

static bool expr_node_equiv(struct bcf_expr *e0, struct bcf_expr *e1)
{
	if (e0->code != e1->code || e0->vlen != e1->vlen ||
	    e0->params != e1->params)
		return false;

	if (is_leaf_node(e0))
		for (u32 i = 0; i < e1->vlen; i++)
			if (e0->args[i] != e1->args[i])
				return false;

	return true;
}

/* Once the equivalence of e0 and e1 are established, we can merge their args.
 * For each arg a0 arg a1 of them, we know the arg must also be equiv; hence,
 * use min(a0, a1) for both e0 and e1, release the other arg.
 *
 * This makes future comparison fast, since we don't need to dfs into the arg
 * again, and this also allows releasing the equivalent exprs early.
 */
static void make_arg_sharing(struct bcf_checker_state *st, struct bcf_expr *e0,
			     struct bcf_expr *e1)
{
	if (WARN_ON_ONCE(e1->vlen != e0->vlen))
		return;

	for (u32 i = 0; i < e0->vlen; i++) {
		if (e0->args[i] == e1->args[i])
			continue;
		/* Share the smaller id so that we converge to the static exprs. */
		if (e0->args[i] < e1->args[i]) {
			expr_id_put(st, e1->args[i]);
			expr_id_get(st, e0->args[i]);
			e1->args[i] = e0->args[i];
		} else {
			expr_id_put(st, e0->args[i]);
			expr_id_get(st, e1->args[i]);
			e0->args[i] = e1->args[i];
		}
	}
}

/* Compare the equivalence of e0 and e1, merge the args if they own the args. */
static int __expr_equiv(struct bcf_checker_state *st, struct bcf_expr *e0,
			struct bcf_expr *e1, bool from_checker, bool own_args)
{
	struct bcf_cmp_stack_elem *stack = st->stack.cmp;
	struct bcf_var_map map = { 0 };
	u32 sp = 0;
	int ret;

	if (!expr_node_equiv(e0, e1))
		return 0;
	/* Vars from the checker must be the same node;
	 * For other cases, use the var_map.
	 */
	if (is_var(e0->code) && from_checker && e0 != e1)
		return 0;
	if (is_leaf_node(e0) || e0 == e1)
		return 1;

	stack[sp++] = (struct bcf_cmp_stack_elem){ e0, e1, 0 };

	while (sp) {
		struct bcf_cmp_stack_elem *cmp = &stack[sp - 1];
		bool pop = true;

		while (cmp->cur_arg < cmp->e0->vlen) {
			u32 arg0 = cmp->e0->args[cmp->cur_arg];
			u32 arg1 = cmp->e1->args[cmp->cur_arg];
			struct bcf_expr *a0, *a1;

			cmp->cur_arg++;

			if (from_checker && arg0 == arg1)
				continue;

			a0 = id_to_expr(st, arg0);
			a1 = from_checker ? id_to_expr(st, arg1) :
					    st->goal_exprs + arg1;

			if (!expr_node_equiv(a0, a1))
				return 0;

			if (is_var(a0->code)) {
				ret = var_equiv(&map, arg0, arg1, from_checker);
				if (ret != 1)
					return ret;
				continue;
			}

			if (is_leaf_node(a0))
				continue;

			if (sp >= BCF_MAX_CMP_STACK)
				return -E2BIG;

			stack[sp++] = (struct bcf_cmp_stack_elem){ a0, a1, 0 };
			pop = false;
			break;
		}

		if (pop) {
			sp--;
			if (own_args)
				make_arg_sharing(st, cmp->e0, cmp->e1);
		}
	}

	return 1;
}

static int expr_equiv(struct bcf_checker_state *st, struct bcf_expr *e0,
		      struct bcf_expr *e1)
{
	/* own_args is false since the e0/e1 may be tmp exprs. */
	return __expr_equiv(st, e0, e1, /* from_checker */ true,
			    /* own_args */ false);
}

static int expr_id_equiv(struct bcf_checker_state *st, u32 i0, u32 i1)
{
	/* Each id increases the expr ref, hence owns the expr and its args. */
	return __expr_equiv(st, id_to_expr(st, i0), id_to_expr(st, i1), true,
			    true);
}

static int check_assume(struct bcf_checker_state *st,
			struct bcf_proof_step *step)
{
	struct bcf_expr *proof_goal, *goal;

	ENSURE(!step->premise_cnt && step->param_cnt == 1);
	proof_goal = get_bool_arg(st, step->args[0]);
	CHECK_PTR(proof_goal);

	if (!st->goal_exprs)
		return 0; /* Proof check only without goal. */
	goal = st->goal_exprs + st->goal;
	ENSURE(__expr_equiv(st, proof_goal, goal, false, false) == 1);
	return 0;
}

static bool is_assume(u16 rule)
{
	return rule == (BCF_RULE_CORE | BCF_RULE_ASSUME);
}

static u16 rule_class_max(u16 rule)
{
	switch (BCF_RULE_CLASS(rule)) {
	case BCF_RULE_CORE:
		return __MAX_BCF_CORE_RULES;
	case BCF_RULE_BOOL:
		return __MAX_BCF_BOOL_RULES;
	case BCF_RULE_BV:
		return __MAX_BCF_BV_RULES;
	default:
		return 0;
	}
}

static int check_steps(struct bcf_checker_state *st, bpfptr_t bcf_buf,
		       u32 step_size)
{
	u32 pos = 0, cur_step = 0, rule;
	struct bcf_proof_step *step;
	bool goal_found = false;
	int err;

	st->steps = kvmemdup_bpfptr(bcf_buf,
				    step_size * sizeof(struct bcf_proof_step));
	if (IS_ERR(st->steps)) {
		err = PTR_ERR(st->steps);
		st->steps = NULL;
		return err;
	}
	st->step_size = step_size;

	/* First pass: validate each step and count how many there are.  While
	 * iterating we also ensure that premises only reference *earlier* steps.
	 */
	while (pos < step_size) {
		step = st->steps + pos;
		rule = BCF_STEP_RULE(step->rule);

		ENSURE(pos + STEP_SZ(step) <= step_size);
		ENSURE(rule && rule < rule_class_max(step->rule));

		/* Every step must only refer to previous established steps */
		bcf_for_each_pm_step(step_id, step)
			ENSURE(step_id < cur_step);

		/* Must introduce a goal that is consistent to the one required */
		if (is_assume(step->rule)) {
			ENSURE(!goal_found); /* only one goal intro step */
			goal_found = true;

			err = check_assume(st, step);
			if (err)
				return err;
		}

		pos += STEP_SZ(step);
		cur_step++;
	}

	/* No trailing garbage and at least two valid steps. */
	ENSURE(pos == step_size && cur_step >= 2 && goal_found);

	st->step_cnt = cur_step;
	st->step_state =
		kvcalloc(cur_step, sizeof(*st->step_state), GFP_KERNEL);
	if (!st->step_state) {
		kvfree(st->steps);
		st->steps = NULL;
		return -ENOMEM;
	}

	/* Second pass: fill in last reference index for each step. */
	for (pos = 0, cur_step = 0; pos < step_size; cur_step++) {
		step = st->steps + pos;
		bcf_for_each_pm_step(step_id, step)
			st->step_state[step_id].last_ref = cur_step;

		pos += STEP_SZ(step);
	}

	/* Every step (except the last one) must be referenced by at
	 * least one later step.
	 */
	for (cur_step = 0; cur_step < st->step_cnt - 1; cur_step++)
		ENSURE(st->step_state[cur_step].last_ref);

	return 0;
}

/* Set the conclusion/fact for the current proof step.
 *
 * If expr_ref 'fact' is provided, takes ownership of the expr_ref and
 * stores its ID and expression pointer in the current step state.
 * If 'fact' is NULL, uses the provided 'fact_id', increments its ref
 * count, resolves it to an expression pointer, and stores both.
 *
 * For each premise step, if the current step is marked as the last
 * reference to that premise (via last_ref), the premise's conclusion
 * is released.
 */
static void __set_step_fact(struct bcf_checker_state *st,
			    struct bcf_expr_ref *fact, u32 fact_id)
{
	struct bcf_step_state *step_st = &st->step_state[st->cur_step];
	struct bcf_proof_step *step = &st->steps[st->cur_step_idx];

	if (fact) {
		/* Take ownership */
		step_st->fact_id = fact->id;
		step_st->fact = &fact->expr;
	} else {
		expr_id_get(st, fact_id);
		step_st->fact = id_to_expr(st, fact_id);
		step_st->fact_id = fact_id;
	}

	bcf_for_each_pm_step(step_id, step) {
		struct bcf_step_state *pm_st = &st->step_state[step_id];

		/* NULL check is necessary because the current step may refer
		 * the same premise multiple times, the check ensures its fact
		 * is only put once.
		 */
		if (pm_st->last_ref == st->cur_step && pm_st->fact) {
			expr_put(st, pm_st->fact);
			pm_st->fact = NULL;
		}
	}
}

static int set_step_fact(struct bcf_checker_state *st,
			 struct bcf_expr_ref *fact)
{
	CHECK_PTR(fact);
	__set_step_fact(st, fact, 0);
	return 0;
}

static int set_step_fact_id(struct bcf_checker_state *st, u32 fact_id)
{
	__set_step_fact(st, NULL, fact_id);
	return 0;
}

static int apply_trusted_step(struct bcf_checker_state *st, char *rule_name,
			      u32 fact_id)
{
	pr_warn("; WARNING: applying trusted step %s\n", rule_name);
	return set_step_fact_id(st, fact_id);
}

static struct bcf_expr *get_premise(struct bcf_checker_state *st,
				    struct bcf_proof_step *step, u32 arg)
{
	return st->step_state[step->args[arg]].fact;
}

static u32 get_premise_id(struct bcf_checker_state *st,
			  struct bcf_proof_step *step, u32 arg)
{
	return st->step_state[step->args[arg]].fact_id;
}

static struct bcf_expr *get_expr_buf(struct bcf_checker_state *st)
{
	st->expr_buf.code = 0;
	st->expr_buf.vlen = 0;
	st->expr_buf.params = 0;
	return (struct bcf_expr *)&st->expr_buf;
}

/* Sign extend val (of `bw` bitwidth) to s64 form. */
static s64 sign_extend_val(u64 val, u8 bw)
{
	u64 m;

	val &= bv_max(bw);
	m = 1ULL << (bw - 1);
	return (s64)((val ^ m) - m);
}

static int eval_bool_expr(struct bcf_checker_state *st, struct bcf_expr *expr,
			  bool *res, struct bcf_eval_stack_elem *sub_vals)
{
	s64 s = 0, d = 0;
	u8 op;

	op = BCF_OP(expr->code);
	if (op == BPF_JSGT || op == BPF_JSGE || op == BPF_JSLT ||
	    op == BPF_JSLE) {
		u8 bw;

		bw = bv_size(id_to_expr(st, expr->args[0]));
		s = sign_extend_val(sub_vals[0].bv_res, bw);
		d = sign_extend_val(sub_vals[1].bv_res, bw);
	}

	switch (op) {
	case BCF_VAL:
		*res = BCF_BOOL_LITERAL(expr->params);
		break;
	case BCF_NOT:
		*res = !sub_vals[0].bool_res;
		break;
	case BCF_CONJ:
		*res = sub_vals[0].bool_res;
		for (u8 i = 1; i < expr->vlen; i++)
			*res &= sub_vals[i].bool_res;
		break;
	case BCF_DISJ:
		*res = sub_vals[0].bool_res;
		for (u8 i = 1; i < expr->vlen; i++)
			*res |= sub_vals[i].bool_res;
		break;
	case BCF_XOR:
		*res = sub_vals[0].bool_res;
		for (u8 i = 1; i < expr->vlen; i++)
			*res ^= sub_vals[i].bool_res;
		break;
	case BCF_IMPLIES:
		*res = !sub_vals[0].bool_res || sub_vals[1].bool_res;
		break;
	case BCF_ITE:
		*res = sub_vals[0].bool_res ? sub_vals[1].bool_res :
					      sub_vals[2].bool_res;
		break;
	case BCF_BITOF:
		*res = (sub_vals[0].bv_res >> BCF_BITOF_BIT(expr->params)) & 1;
		break;
	case BPF_JEQ: {
		struct bcf_expr *a0 = id_to_expr(st, expr->args[0]);

		if (is_bool(a0->code))
			*res = (sub_vals[0].bool_res == sub_vals[1].bool_res);
		else
			*res = (sub_vals[0].bv_res == sub_vals[1].bv_res);
		break;
	}
	case BPF_JNE: {
		struct bcf_expr *a0 = id_to_expr(st, expr->args[0]);

		if (is_bool(a0->code))
			*res = (sub_vals[0].bool_res != sub_vals[1].bool_res);
		else
			*res = (sub_vals[0].bv_res != sub_vals[1].bv_res);
		break;
	}
	case BPF_JGT:
		*res = sub_vals[0].bv_res > sub_vals[1].bv_res;
		break;
	case BPF_JGE:
		*res = sub_vals[0].bv_res >= sub_vals[1].bv_res;
		break;
	case BPF_JLT:
		*res = sub_vals[0].bv_res < sub_vals[1].bv_res;
		break;
	case BPF_JLE:
		*res = sub_vals[0].bv_res <= sub_vals[1].bv_res;
		break;
	case BPF_JSGT:
		*res = s > d;
		break;
	case BPF_JSGE:
		*res = s >= d;
		break;
	case BPF_JSLT:
		*res = s < d;
		break;
	case BPF_JSLE:
		*res = s <= d;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int eval_bv_expr(struct bcf_checker_state *st, struct bcf_expr *expr,
			u64 *res, struct bcf_eval_stack_elem *sub_vals,
			bool *check_overflow)
{
	bool overflow = false;
	u64 mask;
	u8 op;

	op = BCF_OP(expr->code);
	if (bv_size(expr) > 64)
		return -E2BIG;
	mask = bv_max(bv_size(expr));

	switch (op) {
	case BCF_VAL:
		*res = bv_val(expr);
		break;
	case BCF_ITE: {
		struct bcf_expr *cond = id_to_expr(st, expr->args[0]);
		bool cond_res = is_bv(cond->code) ? sub_vals[0].bv_res :
						    sub_vals[0].bool_res;

		*res = cond_res ? sub_vals[1].bv_res : sub_vals[2].bv_res;
		break;
	}
	case BPF_ADD:
		*res = 0;
		for (u8 i = 0; i < expr->vlen; i++)
			overflow |= check_add_overflow(*res, sub_vals[i].bv_res,
						       res);
		break;
	case BPF_SUB:
		overflow |= check_sub_overflow(sub_vals[0].bv_res,
					       sub_vals[1].bv_res, res);
		break;
	case BPF_MUL:
		*res = 1;
		for (u8 i = 0; i < expr->vlen; i++)
			overflow |= check_mul_overflow(*res, sub_vals[i].bv_res,
						       res);
		break;
	case BPF_DIV:
		ENSURE(sub_vals[1].bv_res != 0);
		*res = div64_u64(sub_vals[0].bv_res, sub_vals[1].bv_res);
		break;
	case BPF_MOD:
		ENSURE(sub_vals[1].bv_res != 0);
		div64_u64_rem(sub_vals[0].bv_res, sub_vals[1].bv_res, res);
		break;
	case BPF_OR:
		*res = 0;
		for (u8 i = 0; i < expr->vlen; i++)
			*res |= sub_vals[i].bv_res;
		break;
	case BPF_AND:
		*res = sub_vals[0].bv_res;
		for (u8 i = 1; i < expr->vlen; i++)
			*res &= sub_vals[i].bv_res;
		break;
	case BPF_XOR:
		*res = 0;
		for (u8 i = 0; i < expr->vlen; i++)
			*res ^= sub_vals[i].bv_res;
		break;
	case BPF_NEG: {
		u64 sub = sub_vals[0].bv_res;

		ENSURE((sub & mask) != (1u << (bv_size(expr) - 1)));
		*res = -sign_extend_val(sub, bv_size(expr));
		*res &= mask;
		break;
	}
	case BPF_LSH:
		overflow |= check_shl_overflow(sub_vals[0].bv_res,
					       sub_vals[1].bv_res, res);
		break;
	case BPF_RSH:
		*res = sub_vals[0].bv_res >> sub_vals[1].bv_res;
		break;
	case BPF_ARSH: {
		s64 s = sign_extend_val(sub_vals[0].bv_res, bv_size(expr));
		*res = s >> sub_vals[1].bv_res;
		break;
	}
	case BCF_EXTRACT: {
		u32 start = BCF_EXTRACT_START(expr->params);
		u32 end = BCF_EXTRACT_END(expr->params);

		*res = (sub_vals[0].bv_res >> end) & bv_max(start - end + 1);
		break;
	}
	case BCF_CONCAT: {
		struct bcf_expr *arg;

		*res = 0;
		for (u8 i = 0; i < expr->vlen; i++) {
			arg = id_to_expr(st, expr->args[i]);
			*res <<= bv_size(arg);
			*res |= sub_vals[i].bv_res;
		}
		break;
	}
	case BCF_SIGN_EXTEND: {
		struct bcf_expr *arg;

		arg = id_to_expr(st, expr->args[0]);
		*res = sign_extend_val(sub_vals[0].bv_res, bv_size(arg));
		break;
	}
	case BCF_ZERO_EXTEND:
		*res = sub_vals[0].bv_res;
		break;
	case BCF_BVSIZE:
		*res = bv_size(id_to_expr(st, expr->args[0]));
		break;
	case BCF_FROM_BOOL: {
		*res = 0;
		for (u8 i = 0; i < expr->vlen; i++)
			*res |= ((u64)sub_vals[i].bool_res) << i;
		break;
	}
	case BCF_SDIV:
	case BCF_SMOD:
		return -ENOTSUPP;
	default:
		return -EINVAL;
	}

	if (*res > mask)
		overflow = true;
	if (check_overflow)
		*check_overflow |= overflow;
	*res &= mask;
	return 0;
}

static bool is_constant(struct bcf_expr *e)
{
	return is_val(e->code) || is_bv_bvsize(e->code);
}

static int do_eval_const(struct bcf_checker_state *st, struct bcf_expr *expr,
			 struct bcf_eval_stack_elem *frame,
			 struct bcf_eval_stack_elem *sub_vals, bool *overflow)
{
	int err;

	if (is_bv(expr->code))
		err = eval_bv_expr(st, expr, &frame->bv_res, sub_vals,
				   overflow);
	else if (is_bool(expr->code))
		err = eval_bool_expr(st, expr, &frame->bool_res, sub_vals);
	else
		return -EFAULT;

	/* Evaluated, set to NULL. */
	if (!err)
		frame->expr = NULL;
	return err;
}

struct bcf_eval_result {
	u64 bv_res;
	bool bool_res;
	bool overflow;
};

/* Evaluate a constant expression rooted at `expr_id`.
 * On success returns 0 and sets *res to a boolean/bv literal.
 */
static int eval_const_expr(struct bcf_checker_state *st, u32 expr_id,
			   struct bcf_eval_result *res)
{
	struct bcf_eval_stack_elem *stack = st->stack.eval;
	bool *overflow = &res->overflow;
	struct bcf_expr *root;
	u32 sp = 0;
	int err;

	root = id_to_expr(st, expr_id);
	ENSURE((is_bv(root->code) && bv_size(root) <= 64) ||
	       is_bool(root->code));
	ENSURE(!is_var(root->code));

	stack[sp++] = (struct bcf_eval_stack_elem){
		.expr = root,
		.cur_arg = 0,
	};

	while (sp) {
		struct bcf_eval_stack_elem *top;
		int top_idx;
		u32 vlen;

		/* Terminate when the only frame left is a value frame */
		if (sp == 1 && stack[0].expr == NULL)
			break;

		/* Find the nearest frame that still has an expr */
		top_idx = sp - 1;
		while (top_idx >= 0 && stack[top_idx].expr == NULL)
			top_idx--;
		if (top_idx < 0) /* unreachable */
			return -EFAULT;

		top = &stack[top_idx];
		if (is_constant(top->expr)) {
			err = do_eval_const(st, top->expr, top, NULL, overflow);
			if (err)
				return err;
			continue;
		}

		/* Non-constant must have sub-exprs. */
		vlen = top->expr->vlen;
		if (!vlen)
			return -EFAULT;

		if (top->cur_arg < vlen) {
			u32 child_id = top->expr->args[top->cur_arg++];
			struct bcf_expr *child = id_to_expr(st, child_id);

			if (sp >= BCF_MAX_EVAL_STACK)
				return -E2BIG;
			ENSURE(!is_var(child->code));

			stack[sp++] = (struct bcf_eval_stack_elem){
				.expr = child,
				.cur_arg = 0,
			};
			continue;
		}

		/* All children processed – evaluate this node.
		 * Child values are the next vlen frames.
		 */
		if (top_idx + vlen + 1 != sp)
			return -EFAULT;

		/* Replace children + node with single value frame */
		err = do_eval_const(st, top->expr, top, top + 1, overflow);
		if (err)
			return err;
		sp -= vlen;
	}

	/* Root value frame is stack[0] */
	if (is_bool(root->code))
		res->bool_res = stack[0].bool_res;
	else
		res->bv_res = stack[0].bv_res;

	return 0;
}

static void set_bv_sz(struct bcf_expr *e, u8 sz)
{
	if (WARN_ON_ONCE(is_bv_extract(e->code) || is_bv_from_bool(e->code)))
		return;
	e->params &= 0xff00;
	e->params |= sz;
}

static void set_bv_val(struct bcf_expr *bv, u64 val)
{
	u8 vlen = bv_val_vlen(bv_size(bv));

	bv->code = BCF_BV | BCF_VAL;
	bv->vlen = vlen;
	bv->args[0] = val;
	if (vlen > 1) {
		WARN_ON_ONCE(vlen != 2);
		bv->args[1] = val >> 32;
	}
}

static bool is_aci(u8 code)
{
	/* associative & commutative & idempotency */
	switch (code) {
	case (BCF_BOOL | BCF_CONJ):
	case (BCF_BOOL | BCF_DISJ):
	case (BCF_BV | BPF_AND):
	case (BCF_BV | BPF_OR):
		return true;
	default:
		return false;
	}
}

static bool is_ac(u8 code)
{
	/* associative & commutative */
	return is_aci(code) || is_bv_xor(code);
}

static bool is_assoc(u8 code)
{
	/* associative */
	return is_ac(code) || code == (BCF_BV | BCF_CONCAT);
}

/* A nil element is an argument that does not affect the result of an operation.
 * For example, zero is the nil element for addition, since adding zero leaves
 * the value unchanged.
 */
static bool __nil_elem(struct bcf_expr *root, struct bcf_expr *arg, bool set)
{
	u8 ty = BCF_TYPE(root->code);
	u8 op = BCF_OP(root->code);
	bool is_nil = false;

	if (ty == BCF_BOOL) {
		switch (op) {
		case BCF_DISJ:
			is_nil = is_false(arg);
			if (set)
				*arg = bcf_bool_false;
			break;
		case BCF_CONJ:
			is_nil = is_true(arg);
			if (set)
				*arg = bcf_bool_true;
			break;
		default:
			return false;
		}
	} else if (ty == BCF_BV) {
		u64 nil_val;

		if (bv_size(root) > 64)
			return false;

		switch (op) {
		case BPF_AND:
			nil_val = bv_max(bv_size(root));
			break;
		case BPF_OR:
		case BPF_XOR:
		case BPF_ADD:
			nil_val = 0;
			break;
		case BPF_MUL:
			nil_val = 1;
			break;
		default:
			return false;
		}

		is_nil = is_bv_val(arg->code) && bv_val(arg) == nil_val;
		if (set) {
			if (!WARN_ON_ONCE(arg->vlen <
					  bv_val_vlen(bv_size(root)))) {
				arg->code = (BCF_BV | BCF_VAL);
				set_bv_sz(arg, bv_size(root));
				set_bv_val(arg, nil_val);
			}
		}
	}

	return is_nil;
}

static bool is_nil_elem(struct bcf_expr *root, struct bcf_expr *arg)
{
	return __nil_elem(root, arg, false);
}

static bool set_nil_elem(struct bcf_expr *root, struct bcf_expr *arg)
{
	return __nil_elem(root, arg, true);
}

struct bcf_expr_stack_elem {
	struct bcf_expr *expr;
	u32 cur_arg;
};
#define BCF_MAX_ITER_STACK 64

static int aci_normalize(struct bcf_checker_state *st, struct bcf_expr *root,
			 struct bcf_expr *res)
{
	struct bcf_expr_stack_elem stack[BCF_MAX_ITER_STACK];
	u32 sp = 0;

	if (!is_assoc(root->code)) {
		memcpy(res, root, EXPR_SZ(root) * sizeof(u32));
		return 0;
	}

	res->vlen = 0;
	stack[sp++] =
		(struct bcf_expr_stack_elem){ .expr = root, .cur_arg = 0 };

	while (sp) {
		struct bcf_expr_stack_elem *frame = &stack[sp - 1];
		struct bcf_expr *cur, *arg;
		bool dup = false;
		u32 arg_id;

		cur = frame->expr;
		if (frame->cur_arg >= cur->vlen) {
			sp--;
			continue;
		}

		arg_id = cur->args[frame->cur_arg++];
		arg = id_to_expr(st, arg_id);
		/* Eliminate nil elements */
		if (is_nil_elem(root, arg))
			continue;

		/* Flatten nested same-operator */
		if (arg->code == root->code) {
			if (sp >= BCF_MAX_ITER_STACK)
				return -E2BIG;
			stack[sp++] =
				(struct bcf_expr_stack_elem){ .expr = arg,
							      .cur_arg = 0 };
			continue;
		}

		/* Drop duplicates for idempotent operators */
		if (is_aci(root->code)) {
			for (u32 i = 0; i < res->vlen; i++) {
				int ret =
					expr_id_equiv(st, res->args[i], arg_id);
				if (ret < 0)
					return ret;
				if (ret == 1) {
					dup = true;
					break;
				}
			}
			if (dup)
				continue;
		}

		if (res->vlen >= U8_MAX)
			return -E2BIG;

		res->args[res->vlen++] = arg_id;
	}

	if (!res->vlen) {
		set_nil_elem(root, res);
	} else {
		res->code = root->code;
		res->params = root->params;
	}

	return 0;
}

static int __cmp_u32(const void *a, const void *b)
{
	return *(u32 *)a - *(u32 *)b;
}

/* For a = b, check if norm(a) = norm(b) */
static int check_aci_norm(struct bcf_checker_state *st, struct bcf_expr *eq)
{
	DEFINE_RAW_FLEX(struct bcf_expr, bn, args, U8_MAX);
	struct bcf_expr *a, *b; /* original */
	struct bcf_expr *an; /* normalized */
	int err;

	a = id_to_expr(st, eq->args[0]);
	b = id_to_expr(st, eq->args[1]);

	an = get_expr_buf(st);
	err = aci_normalize(st, a, an);
	err = err ?: aci_normalize(st, b, bn);
	if (err)
		return err;

	if (an->vlen == 1 && reducible_variadic(an->code))
		an = id_to_expr(st, an->args[0]);
	if (bn->vlen == 1 && reducible_variadic(bn->code))
		bn = id_to_expr(st, bn->args[0]);

	if (a->code == b->code) {
		if (expr_equiv(st, an, bn) == 1)
			return 0;

		if (is_assoc(a->code)) {
			sort(an->args, an->vlen, sizeof(u32), __cmp_u32, NULL);
			sort(bn->args, bn->vlen, sizeof(u32), __cmp_u32, NULL);
			ENSURE(expr_equiv(st, an, bn) == 1);
		} else {
			return -EINVAL;
		}
	} else {
		ENSURE(expr_equiv(st, a, bn) == 1 ||
		       expr_equiv(st, an, b) == 1);
	}
	return 0;
}

static bool is_zero_elem(struct bcf_expr *root, struct bcf_expr *arg)
{
	switch (root->code) {
	case (BCF_BOOL | BCF_DISJ):
		return is_true(arg);
	case (BCF_BOOL | BCF_CONJ):
		return is_false(arg);
	case (BCF_BV | BPF_AND): {
		if (!is_bv_val(arg->code))
			return false;
		return bv_val(arg) == 0;
	}
	case (BCF_BV | BPF_OR): {
		u64 mask = bv_max(bv_size(root));

		if (!is_bv_val(arg->code))
			return false;
		return bv_val(arg) == mask;
	}
	default:
		return false;
	}
}

/* Depth-first search to determine whether `arg` evaluates to the zero
 * element because at least one child is that zero and the operators along
 * the path is the same as the root.
 */
static int check_absorb(struct bcf_checker_state *st, struct bcf_expr *eq)
{
	struct bcf_expr_stack_elem stack[BCF_MAX_ITER_STACK];
	struct bcf_expr *root, *zero;
	u32 sp = 0;

	root = id_to_expr(st, eq->args[0]);
	zero = id_to_expr(st, eq->args[1]);
	ENSURE(is_zero_elem(root, zero));

	stack[sp++] =
		(struct bcf_expr_stack_elem){ .expr = root, .cur_arg = 0 };

	while (sp) {
		struct bcf_expr_stack_elem *frame = &stack[sp - 1];
		struct bcf_expr *cur = frame->expr;
		u32 child_id;

		if (is_zero_elem(root, cur))
			return 0;

		if (frame->cur_arg >= cur->vlen || cur->code != root->code) {
			sp--;
			continue;
		}

		if (sp >= BCF_MAX_CMP_STACK)
			return -E2BIG;

		child_id = cur->args[frame->cur_arg++];
		stack[sp++] = (struct bcf_expr_stack_elem){
			.expr = id_to_expr(st, child_id), .cur_arg = 0
		};
	}

	return -EINVAL;
}

#define BCF_REWRITE_STRUCT_NAME(_name) __bcf_rw_##_name
#include "bcf_rewrite_dsl.h"
#include "bcf_rewrites.h"

#define __MAKE_REWRITE_TB(_name) \
	[BCF_REWRITE_##_name] = &BCF_REWRITE_STRUCT_NAME(_name),
static const struct bcf_rewrite *const bcf_rewrites[__MAX_BCF_REWRITES] = {
	[0 ... __MAX_BCF_REWRITES - 1] = NULL,
	BCF_REWRITES_TABLE(__MAKE_REWRITE_TB)
};
#undef __MAKE_REWRITE_TB

#include "bcf_rewrite_dsl_cleanup.h"
#undef BCF_REWRITE_STRUCT_NAME

static int rw_type_check(struct bcf_checker_state *st,
			 const struct bcf_expr_nullary *ty,
			 struct bcf_expr *expr)
{
	bool ty_match;

	if (rw_type_any(ty))
		return 0;

	if (rw_type_bvany(ty))
		ty_match = is_bv(expr->code);
	else if (rw_type_list_bvany(ty))
		ty_match = is_list(expr->code) &&
			   BCF_LIST_TYPE(expr->params) == BCF_BV;
	else
		ty_match = same_type((void *)ty, expr);

	return ty_match ? 0 : -EINVAL;
}

static int pack_bv_params(struct bcf_checker_state *st, struct bcf_expr *expr,
			  u32 val_id, bool low)
{
	struct bcf_expr *val = id_to_expr(st, val_id);
	struct bcf_eval_result res = { 0 };
	int err;

	BUG_ON(!is_bv(val->code));
	err = eval_const_expr(st, val_id, &res);
	if (err)
		return err;
	ENSURE(!res.overflow && res.bv_res <= U8_MAX);

	if (low)
		expr->params |= (u8)res.bv_res;
	else
		expr->params |= (u16)res.bv_res << 8;

	expr_id_put(st, val_id);
	return 0;
}

struct bcf_rw_parse_state {
	const struct bcf_expr_nullary *rw_expr;
	u32 expr_id;
	u32 cur_arg;
	u32 size;
};

static int convert_rw_expr(struct bcf_checker_state *st,
			   struct bcf_rw_parse_state *cur)
{
	struct bcf_expr *expr = id_to_expr(st, cur->expr_id);
	struct bcf_eval_result eval_res = { 0 };
	struct bcf_expr *arg, *expr_buf;
	bool encode_low = false;
	int err;

	/* Pack indexed op into its params. */
	switch (expr->code) {
	case (BCF_BOOL | BCF_BITOF):
		encode_low = true;
		fallthrough;
	case (BCF_BV | BCF_REPEAT):
	case (BCF_BV | BCF_ZERO_EXTEND):
	case (BCF_BV | BCF_SIGN_EXTEND): {
		if (WARN_ON_ONCE(expr->vlen != 2))
			return -EFAULT;
		err = pack_bv_params(st, expr, expr->args[0], encode_low);
		if (err)
			return err;
		expr->vlen = 1;
		expr->args[0] = expr->args[1];
		break;
	}
	case (BCF_BV | BCF_EXTRACT): {
		if (WARN_ON_ONCE(expr->vlen != 3))
			return -EFAULT;
		err = pack_bv_params(st, expr, expr->args[0], false);
		err = err ?: pack_bv_params(st, expr, expr->args[1], true);
		if (err)
			return err;
		expr->vlen = 1;
		expr->args[0] = expr->args[2];
		break;
	}
	default:
		break;
	}
	if (is_rw_sym_val(cur->rw_expr)) {
		/* @bv val size */
		if (WARN_ON_ONCE(expr->vlen != 2))
			return -EFAULT;
		u32 val_expr_id = expr->args[0];
		u32 size_expr_id = expr->args[1];
		err = pack_bv_params(st, expr, size_expr_id, true);
		err = err ?: eval_const_expr(st, val_expr_id, &eval_res);
		if (err)
			return err;
		if (WARN_ON_ONCE(bv_size(expr) > 64 ||
				 eval_res.bv_res > bv_max(bv_size(expr))))
			return -EFAULT;
		set_bv_val(expr, eval_res.bv_res);
		expr_id_put(st, val_expr_id);
	} else if (is_rw_bvmax(cur->rw_expr)) {
		u32 vlen;
		/* @bvmax size */
		err = pack_bv_params(st, expr, expr->args[0], true);
		if (err)
			return err;
		if (WARN_ON_ONCE(bv_size(expr) > 64))
			return -EFAULT;
		vlen = bv_val_vlen(bv_size(expr));
		if (vlen > expr->vlen) {
			expr = realloc_expr(st, cur->expr_id, vlen);
			CHECK_PTR(expr);
		}
		set_bv_val(expr, bv_max(bv_size(expr)));
	} else if (is_bool_ite(cur->rw_expr->code)) {
		/* Unlike BV_ITE, ITE is generic over types. */
		if (WARN_ON_ONCE(expr->vlen != 3))
			return -EFAULT;
		struct bcf_expr *ite_branch = id_to_expr(st, expr->args[1]);
		expr->code = BCF_ITE;
		if (WARN_ON_ONCE(is_list(ite_branch->code)))
			return -EFAULT;
		expr->code |= BCF_TYPE(ite_branch->code);
	}

	/* Flatten list operands:
	 * If an operator with id-args receives list-typed children, splice their
	 * elements into the argument list. This keeps variadic ops flat. Invalid
	 * arities/types are caught by subsequent type_check().
	 */
	if (expr->vlen && expr_arg_is_id(expr->code)) {
		expr_buf = get_expr_buf(st);
		bcf_for_each_arg_expr(arg_i, arg, expr, st) {
			if (is_list(arg->code)) {
				err = append_expr_args(expr_buf, arg);
				if (err)
					return err;
			} else {
				if (expr_buf->vlen >= U8_MAX)
					return -E2BIG;
				expr_buf->args[expr_buf->vlen++] =
					expr->args[arg_i];
			}
		}
		if (WARN_ON_ONCE(!expr_buf->vlen)) {
			return -ENOTSUPP;
		} else if (expr_buf->vlen == 1 &&
			   reducible_variadic(expr->code)) {
			u32 elem = expr_buf->args[0];
			expr_id_get(st, elem);
			expr_put(st, expr);
			cur->expr_id = elem;
			expr = id_to_expr(st, elem);
		} else {
			if (expr_buf->vlen > expr->vlen) {
				expr = realloc_expr(st, cur->expr_id,
						    expr_buf->vlen);
				CHECK_PTR(expr);
			}
			copy_expr_args(expr, expr_buf);
		}
	}

	/* Resolve bv size */
	if (is_bv(expr->code) && expr_arg_is_id(expr->code) && expr->vlen) {
		switch (BCF_OP(expr->code)) {
		case BCF_EXTRACT:
			break;
		case BCF_ITE:
			set_bv_sz(expr, bv_size(id_to_expr(st, expr->args[1])));
			break;
		case BCF_SIGN_EXTEND:
		case BCF_ZERO_EXTEND: {
			u32 ext = BCF_EXT_LEN(expr->params);
			u32 sz = bv_size(id_to_expr(st, expr->args[0]));
			set_bv_sz(expr, sz + ext);
			break;
		}
		case BCF_CONCAT: {
			u32 sz = 0;
			bcf_for_each_expr(arg, expr, st)
				sz += bv_size(arg);
			set_bv_sz(expr, sz);
			break;
		}
		case BCF_BVSIZE:
			set_bv_sz(expr, 32);
			break;
		case BCF_FROM_BOOL:
			set_bv_sz(expr, expr->vlen);
			break;
		case BCF_REPEAT: {
			u32 sz = bv_size(id_to_expr(st, expr->args[0]));
			sz *= BCF_REPEAT_N(expr->params);
			set_bv_sz(expr, sz);
			break;
		}
		default:
			bcf_for_each_expr(arg, expr, st) {
				if (is_bv(arg->code)) {
					set_bv_sz(expr, bv_size(arg));
					break;
				}
			}
			break;
		}
	}

	err = type_check(st, expr);
	if (err)
		return err;

	return 0;
}

static int pop_rw_expr(struct bcf_checker_state *st,
		       struct bcf_rw_parse_state *cur,
		       struct bcf_rw_parse_state *parent)
{
	if (!is_rw_var(cur->rw_expr)) {
		int err = convert_rw_expr(st, cur);
		if (err)
			return err;
	}

	/* Propagate self to parent. */
	if (parent) {
		struct bcf_expr *p_expr = id_to_expr(st, parent->expr_id);
		p_expr->args[p_expr->vlen++] = cur->expr_id;
		parent->size += cur->size;
	}
	return 0;
}

static int push_rw_expr(struct bcf_checker_state *st,
			struct bcf_rw_parse_state *cur,
			struct bcf_rw_parse_state *parent, u32 *args, u32 arg_n)
{
	const struct bcf_expr_nullary *rw_expr = cur->rw_expr;
	const struct bcf_expr *expr = (void *)rw_expr;

	if (is_rw_var(rw_expr)) {
		BUG_ON(rw_expr->vlen);
		cur->expr_id = args[rw_var_id(rw_expr)];
		expr_id_get(st, cur->expr_id);
	} else if (is_true(expr)) {
		cur->expr_id = st->true_expr;
	} else if (is_false(expr)) {
		cur->expr_id = st->false_expr;
	} else if (is_rw_bv_val(rw_expr)) {
		struct bcf_expr_ref *val = alloc_expr(st, rw_expr->vlen);

		CHECK_PTR(val);
		val->code = BCF_BV | BCF_VAL;
		val->vlen = rw_expr->vlen;
		val->params = rw_expr->params;
		for (u32 i = 0; i < rw_expr->vlen; i++)
			val->args[i] = rw_bv_val(rw_expr + i + 1);
		cur->size += rw_expr->vlen; /* skip value nodes */
		cur->cur_arg += rw_expr->vlen;
		cur->expr_id = val->id;
	} else {
		struct bcf_expr_ref *eref = alloc_expr(st, rw_expr->vlen);

		CHECK_PTR(eref);
		if (WARN_ON_ONCE(!rw_expr->vlen))
			return -EFAULT;
		eref->code = rw_expr->code;
		eref->vlen = 0;
		eref->params = 0;
		cur->expr_id = eref->id;
	}

	return 0;
}

static int parse_rw_expr(struct bcf_checker_state *st,
			 const struct bcf_expr_nullary *rw_exprs, u32 len,
			 u32 *args, u32 arg_n, u32 *expr_id)
{
	enum { BCF_MAX_PARSE_STACK = 64 };
	struct bcf_rw_parse_state stack[BCF_MAX_PARSE_STACK];
	u32 sp = 0;
	int err;

	stack[sp++] = (struct bcf_rw_parse_state){
		.rw_expr = rw_exprs,
		.cur_arg = 0,
		.size = 1,
	};
	while (sp) {
		struct bcf_rw_parse_state *cur = &stack[sp - 1];
		struct bcf_rw_parse_state *parent = NULL;

		if (sp > 1)
			parent = &stack[sp - 2];

		if (!cur->cur_arg) {
			err = push_rw_expr(st, cur, parent, args, arg_n);
			if (err)
				return err;
		}

		if (cur->cur_arg < cur->rw_expr->vlen) {
			if (sp >= BCF_MAX_PARSE_STACK)
				return -E2BIG;
			stack[sp++] = (struct bcf_rw_parse_state){
				.rw_expr = cur->rw_expr + cur->size,
				.cur_arg = 0,
				.size = 1,
			};
			cur->cur_arg++;
			continue;
		}

		err = pop_rw_expr(st, cur, parent);
		if (err)
			return err;
		sp--;
	}

	/* Must consume all exprs */
	if (WARN_ON_ONCE(stack[0].size != len))
		return -EFAULT;

	*expr_id = stack[0].expr_id;
	return 0;
}

static bool rw_cond_match(struct bcf_checker_state *st, struct bcf_expr *cond,
			  struct bcf_expr *pm)
{
	if (expr_equiv(st, cond, pm) == 1)
		return true;
	return is_bool_eq(pm->code) && is_true(id_to_expr(st, pm->args[1])) &&
	       (expr_equiv(st, cond, id_to_expr(st, pm->args[0])) == 1);
}

static int apply_rewrite(struct bcf_checker_state *st,
			 struct bcf_expr_ref **fact, u32 rid, u32 *pm_steps,
			 u32 pm_step_n, u32 *args, u32 arg_n)
{
	struct bcf_expr_ref *conclusion;
	const struct bcf_rewrite *rw;
	u32 match, target;
	int err;

	ENSURE(rid > BCF_REWRITE_UNSPEC && rid < __MAX_BCF_REWRITES);
	rw = bcf_rewrites[rid];

	/* Param type must match. */
	ENSURE(arg_n == rw->param_cnt);
	for (u32 i = 0; i < arg_n; i++) {
		struct bcf_expr *arg_expr = id_to_expr(st, args[i]);

		err = rw_type_check(st, &rw->params[i], arg_expr);
		if (err)
			return err;
	}

	/* Conditions must be proved. */
	ENSURE(!!rw->cond_len == !!pm_step_n);
	if (rw->cond_len) {
		struct bcf_expr *cond, *pm;
		u32 cond_id;

		err = parse_rw_expr(st, rw->cond, rw->cond_len, args, arg_n,
				    &cond_id);
		if (err)
			return err;
		cond = id_to_expr(st, cond_id);

		if (is_bool_conj(cond->code)) {
			struct bcf_expr *sub;

			ENSURE(cond->vlen == pm_step_n);
			bcf_for_each_arg_expr(i, sub, cond, st) {
				pm = st->step_state[pm_steps[i]].fact;
				ENSURE(rw_cond_match(st, sub, pm));
			}
		} else {
			ENSURE(pm_step_n == 1);
			pm = st->step_state[pm_steps[0]].fact;
			ENSURE(rw_cond_match(st, cond, pm));
		}
		expr_put(st, cond); /* used for check only */
	}

	/* substitude args, and assert match = target. */
	err = parse_rw_expr(st, rw->match, rw->match_len, args, arg_n, &match);
	err = err   ?:
		      parse_rw_expr(st, rw->target, rw->target_len, args, arg_n,
				    &target);
	if (err)
		return err;
	conclusion = build_bool_eq_move(st, match, target);
	CHECK_PTR(conclusion);
	err = type_check(st, &conclusion->expr);
	if (err)
		return err;

	*fact = conclusion;
	return 0;
}

#define RULE_TBL(rule) [BCF_RULE_NAME(rule)] = &&rule,
#define DEFINE_JUMP_TABLE(rule_set)                                  \
	static const void *const                                     \
		checkers[__MAX_##rule_set] __annotate_jump_table = { \
			[0 ... __MAX_##rule_set - 1] = &&bad_rule,   \
			rule_set(RULE_TBL)                           \
		};

static int apply_core_rule(struct bcf_checker_state *st,
			   struct bcf_proof_step *step)
{
	DEFINE_JUMP_TABLE(BCF_CORE_RULES);
	u16 rule = BCF_STEP_RULE(step->rule);
	u8 param_cnt = step->param_cnt;
	u8 pm_cnt = step->premise_cnt;
	struct bcf_expr_ref *fact = NULL;
	struct bcf_expr *premise, *param;
	u32 premise_id;
	int err;

	/* Must refer to valid exprs in the proof. */
	for (u32 arg_i = 0; arg_i < param_cnt; arg_i++) {
		u32 arg_id = step->args[pm_cnt + arg_i];

		if (rule == BCF_RULE_REWRITE || rule == BCF_RULE_CONG)
			break;
		CHECK_PTR(get_arg_expr(st, arg_id));
	}
	goto *checkers[rule];

ASSUME:
	/* Assume only appears once and is already check in `check_steps()`. */
	return set_step_fact_id(st, step->args[0]);

EVALUATE: { /* Evaluate constant boolean/bitvector expression */
	struct bcf_eval_result res = { 0 };
	struct bcf_expr *const_expr;
	u32 res_id;

	ENSURE(!pm_cnt && param_cnt == 1);
	CHECK_PTR(get_arg_expr(st, step->args[0]));

	err = eval_const_expr(st, step->args[0], &res);
	if (err)
		return err;
	ENSURE(!res.overflow);

	const_expr = id_to_expr(st, step->args[0]);
	if (is_bool(const_expr->code)) {
		res_id = res.bool_res ? st->true_expr : st->false_expr;
	} else {
		struct bcf_expr_ref *eref;

		eref = build_bv_val(st, bv_size(const_expr), res.bv_res);
		CHECK_PTR(eref);
		res_id = eref->id;
	}

	fact = build_bool_eq_move(st, step->args[0], res_id);
	return set_step_fact(st, fact);
}

DISTINCT_VALUES: { /* Inequality of distinct values */
	struct bcf_expr *v0, *v1;

	ENSURE(!pm_cnt && param_cnt == 2);

	v0 = id_to_expr(st, step->args[0]);
	v1 = id_to_expr(st, step->args[1]);
	ENSURE(is_val(v0->code) && is_val(v1->code));
	ENSURE(same_type(v0, v1));
	ENSURE(expr_equiv(st, v0, v1) == 0);

	fact = build_bool_eq(st, step->args[0], step->args[1]);
	CHECK_PTR(fact);
	fact = build_bool_not_move(st, fact->id);
	return set_step_fact(st, fact);
}

ACI_NORM: { /* Equality of ACI normal form */
	ENSURE(!pm_cnt && param_cnt == 1);
	param = id_to_expr(st, step->args[0]);
	ENSURE(is_bool_eq(param->code));
	err = check_aci_norm(st, param);
	if (err)
		return err;
	return set_step_fact_id(st, step->args[0]);
}

ABSORB: { /* Absorption of conjunctions */
	ENSURE(!pm_cnt && param_cnt == 1);
	param = id_to_expr(st, step->args[0]);
	ENSURE(is_bool_eq(param->code));
	err = check_absorb(st, param);
	if (err)
		return err;
	return set_step_fact_id(st, step->args[0]);
}

REWRITE: { /* Rewrite equality to equivalent expression */
	u32 arg_n, pm_step_n;
	u32 *args, *pm_steps;
	u32 rewrite_id;

	ENSURE(param_cnt);
	pm_steps = step->args;
	pm_step_n = step->premise_cnt;
	rewrite_id = step->args[pm_step_n];
	args = step->args + step->premise_cnt + 1;
	arg_n = step->param_cnt - 1;

	if (rewrite_id == BCF_REWRITE_UNSPEC) {
		if (arg_n == 1 && !pm_step_n)
			return apply_trusted_step(st, "rewrite", args[0]);
		return -EINVAL;
	}

	err = apply_rewrite(st, &fact, rewrite_id, pm_steps, pm_step_n, args,
			    arg_n);
	if (err)
		return err;
	return set_step_fact(st, fact);
}

REFL: /* A ⊢ A = A */
{
	ENSURE(!pm_cnt && param_cnt == 1);
	CHECK_PTR(get_arg_expr(st, step->args[0]));
	fact = build_bool_eq(st, step->args[0], step->args[0]);
	return set_step_fact(st, fact);
}

SYMM: /* A = B ⊢ B = A */
{
	struct bcf_expr *eq;

	ENSURE(pm_cnt == 1 && !param_cnt);
	premise = get_premise(st, step, 0);
	eq = premise;
	if (is_bool_not(premise->code))
		eq = id_to_expr(st, premise->args[0]);
	ENSURE(is_bool_eq(eq->code));

	fact = build_bool_eq(st, eq->args[1], eq->args[0]);
	CHECK_PTR(fact);
	if (is_bool_not(premise->code))
		fact = build_bool_not_move(st, fact->id);

	return set_step_fact(st, fact);
}

TRANS: /* A = B, B = C ⊢ A = C */
{
	u32 lhs_id = 0, rhs_id = 0;
	bool first = true;

	ENSURE(pm_cnt && !param_cnt);

	bcf_for_each_pm_expr(premise, step, st) {
		ENSURE(is_bool_eq(premise->code));

		if (first) {
			lhs_id = premise->args[0];
			rhs_id = premise->args[1];
			first = false;
		} else {
			/* Transitivity chain: current LHS matches previous RHS */
			// clang-format off
			ENSURE(expr_id_equiv(st, rhs_id, premise->args[0]) == 1);
			// clang-format on
			rhs_id = premise->args[1];
		}
	}

	fact = build_bool_eq(st, lhs_id, rhs_id);
	return set_step_fact(st, fact);
}

CONG: /* A = B ⊢ f(A) = f(B) */
{
	struct bcf_expr *expr_buf = get_expr_buf(st);
	struct bcf_expr_ref *lhs, *rhs;
	u32 *args;

	ENSURE(pm_cnt && param_cnt == 1);
	/* The first param encodes the expr (function) to apply*/
	*(u32 *)expr_buf = step->args[pm_cnt];

	/* Build expression with LHS arguments */
	args = expr_buf->args;
	bcf_for_each_pm_expr(premise, step, st) {
		ENSURE(is_bool_eq(premise->code));
		*args++ = premise->args[0];
	}
	err = type_check(st, expr_buf);
	if (err)
		return err;
	lhs = clone_expr(st, expr_buf);
	CHECK_PTR(lhs);

	/* Build expression with RHS arguments.
	 * LHS is type-checked, so safe to clone.
	 */
	args = expr_buf->args;
	bcf_for_each_pm_expr(premise, step, st) {
		*args++ = premise->args[1];
	}
	rhs = clone_expr(st, expr_buf);
	CHECK_PTR(rhs);

	fact = build_bool_eq_move(st, lhs->id, rhs->id);
	return set_step_fact(st, fact);
}

TRUE_INTRO: /* A ⊢ A = True */
{
	ENSURE(pm_cnt == 1 && !param_cnt);
	premise_id = get_premise_id(st, step, 0);
	fact = build_bool_eq(st, premise_id, st->true_expr);
	return set_step_fact(st, fact);
}

TRUE_ELIM: /* A = True ⊢ A */
{
	ENSURE(pm_cnt == 1 && !param_cnt);
	premise = get_premise(st, step, 0);
	ENSURE(is_bool_eq(premise->code));
	ENSURE(expr_id_equiv(st, premise->args[1], st->true_expr) == 1);
	set_step_fact_id(st, premise->args[0]);
	return 0;
}

FALSE_INTRO: /* ¬A ⊢ A = False */
{
	ENSURE(pm_cnt == 1 && !param_cnt);
	premise = get_premise(st, step, 0);
	ENSURE(is_bool_not(premise->code));
	fact = build_bool_eq(st, premise->args[0], st->false_expr);
	return set_step_fact(st, fact);
}

FALSE_ELIM: /* A = False ⊢ ¬A */
{
	ENSURE(pm_cnt == 1 && !param_cnt);
	premise = get_premise(st, step, 0);
	ENSURE(is_bool_eq(premise->code));
	ENSURE(expr_id_equiv(st, premise->args[1], st->false_expr) == 1);
	fact = build_bool_not(st, premise->args[0]);
	return set_step_fact(st, fact);
}

bad_rule:
	WARN_ONCE(1, "Unknown core rule: %u", BCF_STEP_RULE(step->rule));
	return -EFAULT;
}

/* Parse the polarity and literal indices from the step parameters. */
static int parse_resolution_params(struct bcf_checker_state *st,
				   struct bcf_proof_step *step,
				   u32 **pol_bitmap_out, u32 **lits_out)
{
	u32 pm_cnt = step->premise_cnt;
	u32 lit_cnt = pm_cnt - 1, mask;
	u32 pol_vlen, tail_bits;
	u32 *pol_bitmap, *lits;

	pol_vlen = DIV_ROUND_UP_POW2(lit_cnt, 32);
	ENSURE(pol_vlen + lit_cnt == step->param_cnt);

	pol_bitmap = &step->args[pm_cnt];
	tail_bits = lit_cnt & 31;
	if (tail_bits) {
		mask = ~GENMASK(tail_bits - 1, 0);
		ENSURE((pol_bitmap[pol_vlen - 1] & mask) == 0);
	}

	lits = &step->args[pm_cnt + pol_vlen];
	for (u32 i = 0; i < lit_cnt; i++)
		CHECK_PTR(get_bool_arg(st, lits[i]));

	*pol_bitmap_out = pol_bitmap;
	*lits_out = lits;
	return 0;
}

static int copy_literals(struct bcf_checker_state *st, struct bcf_expr *lits,
			 u32 clause, struct bcf_expr *pivot)
{
	struct bcf_expr *clause_expr;

	clause_expr = id_to_expr(st, clause);
	if (is_bool_disj(clause_expr->code)) {
		int ret;

		ret = expr_equiv(st, clause_expr, pivot);
		if (ret < 0)
			return ret;
		if (ret == 0)
			return copy_expr_args(lits, clause_expr);
	}

	lits->args[0] = clause;
	lits->vlen = 1;
	return 0;
}

static int elim_pivot(struct bcf_checker_state *st, struct bcf_expr *lits,
		      struct bcf_expr *pivot)
{
	struct bcf_expr *lit;
	int ret;

	bcf_for_each_arg_expr(i, lit, lits, st) {
		ret = expr_equiv(st, lit, pivot);
		if (ret < 0)
			return ret;
		if (ret == 0)
			continue;
		remove_expr_arg(st, lits, i, false);
		/* Only eliminate the first occurrence. */
		break;
	}
	return 0;
}

static void get_pivots(struct bcf_checker_state *st, struct bcf_expr **pivots,
		       u32 pivot, bool pol)
{
	st->not_expr = (struct bcf_expr_unary){
		.code = BCF_BOOL | BCF_NOT,
		.vlen = 1,
		.params = 0,
		.arg0 = pivot,
	};
	pivots[0] = id_to_expr(st, pivot);
	pivots[1] = (void *)&st->not_expr;
	if (!pol)
		swap(pivots[0], pivots[1]);
}

#define bcf_test_pol(_nr, _p) ((_p[_nr >> 5] >> (_nr & 31)) & 1)

static int chain_resolution(struct bcf_checker_state *st,
			    struct bcf_proof_step *step)
{
	DEFINE_RAW_FLEX(struct bcf_expr, lhs_lits, args, U8_MAX);
	struct bcf_expr *pivots[2], *rhs_lits;
	u32 *lits = NULL, *pols = NULL;
	u32 pm_cnt = step->premise_cnt;
	u32 lit_cnt = pm_cnt - 1, lhs_pm;
	struct bcf_expr_ref *fact;
	int err;

	/* Parse polarity and pivots */
	err = parse_resolution_params(st, step, &pols, &lits);
	if (err)
		return err;

	/* Set up the first clause */
	lhs_lits->vlen = 0;
	lhs_lits->params = 0;
	lhs_pm = get_premise_id(st, step, 0);
	get_pivots(st, pivots, lits[0], bcf_test_pol(0, pols));
	err = copy_literals(st, lhs_lits, lhs_pm, pivots[0]);
	if (err)
		return err;

	rhs_lits = get_expr_buf(st);
	for (u32 i = 0, rhs = 1; i < lit_cnt; i++, rhs++) {
		u32 rhs_pm = get_premise_id(st, step, rhs);

		get_pivots(st, pivots, lits[i], bcf_test_pol(i, pols));
		err = elim_pivot(st, lhs_lits, pivots[0]);
		err = err ?: copy_literals(st, rhs_lits, rhs_pm, pivots[1]);
		err = err ?: elim_pivot(st, rhs_lits, pivots[1]);
		err = err ?: append_expr_args(lhs_lits, rhs_lits);
		if (err)
			return err;
	}

	if (!lhs_lits->vlen)
		return set_step_fact_id(st, st->false_expr);
	else if (lhs_lits->vlen == 1)
		return set_step_fact_id(st, lhs_lits->args[0]);

	lhs_lits->code = BCF_BOOL | BCF_DISJ;
	fact = clone_expr(st, lhs_lits);
	return set_step_fact(st, fact);
}

/* dup_pair_list: packed byte array for factoring duplicate pairs.
 * Each entry: [pair_len, uniq_idx, dup_idx0, dup_idx1, ...]
 *   - pair_len: total indices in entry (uniq + dups)
 *   - uniq_idx: index of unique literal
 *   - dup_idx*: indices of literals equivalent to uniq_idx
 *
 * Entries are sequential. Example:
 *   [pair_len, uniq0, dup0, dup1, ..., pair_len, uniq1, dup0, ...]
 *
 * Rules:
 *   - Unused bytes must be zero.
 *   - uniq_idx values strictly increasing.
 *   - Within entry: uniq_idx < dup_idx0 < dup_idx1 < ...
 *   - premise->args[uniq_idx] and premise->args[dup_idx*] must be equivalent.
 *   - Set dups_bitmap bit for each dup_idx.
 */
static int parse_dup_pairs(struct bcf_checker_state *st,
			   struct bcf_expr *clause, u32 *params, u32 cnt,
			   unsigned long *dups_bitmap)
{
	u8 *dup_pair_list = (void *)params;
	u32 vlen = cnt * 4, pre_uniq;
	u32 *args = clause->args;
	u32 idx = 0, dup_cnt = 0;
	bool first = true;

	while (idx < vlen) {
		u32 pair_len = dup_pair_list[idx++];
		u8 uniq, *dups;

		if (!pair_len)
			break;

		ENSURE(pair_len >= 2 && idx + pair_len <= vlen);

		uniq = dup_pair_list[idx];
		ENSURE(uniq < clause->vlen);
		if (first)
			first = false;
		else
			ENSURE(uniq > pre_uniq);
		pre_uniq = uniq;

		dups = &dup_pair_list[idx + 1];
		for (u32 i = 0; i < pair_len - 1; i++) {
			ENSURE(dups[i] < clause->vlen && dups[i] > uniq);
			ENSURE(expr_id_equiv(st, args[uniq], args[dups[i]]) ==
			       1);
			set_bit(dups[i], dups_bitmap);
			dup_cnt++;
		}

		idx += pair_len;
	}

	ENSURE(dup_cnt);
	if (idx < vlen)
		ENSURE(!memchr_inv(&dup_pair_list[idx], 0, vlen - idx));

	return 0;
}

static int factoring(struct bcf_checker_state *st, struct bcf_expr *clause,
		     u32 *dup_pairs, u8 vlen)
{
	unsigned long dups[bitmap_size(U8_MAX)] = { 0 };
	struct bcf_expr *dedupped;
	struct bcf_expr_ref *fact;
	int err;

	err = parse_dup_pairs(st, clause, dup_pairs, vlen, dups);
	if (err)
		return err;

	dedupped = get_expr_buf(st);
	dedupped->code = BCF_BOOL | BCF_DISJ;
	for (u32 i = 0; i < clause->vlen; i++) {
		if (test_bit(i, dups))
			continue;
		dedupped->args[dedupped->vlen++] = clause->args[i];
	}

	if (dedupped->vlen == 1)
		return set_step_fact_id(st, dedupped->args[0]);

	fact = clone_expr(st, dedupped);
	return set_step_fact(st, fact);
}

/* Apply a sequence of swaps to reorder the arguments of a clause.
 *
 * The swap instructions are encoded as a vector of u16 pairs in step->args,
 * starting after the premise ids. The first u16 is the number of swaps,
 * followed by that u16 values, each encoding a swap between two indices:
 *   - lower 8 bits: index j
 *   - upper 8 bits: index k
 * The function clones the input clause, applies the swaps in order, and
 * returns the reordered clause.
 */
static struct bcf_expr_ref *apply_reordering(struct bcf_checker_state *st,
					     struct bcf_expr *pm,
					     struct bcf_proof_step *step)
{
	u16 *swaps_vec = (u16 *)&step->args[step->premise_cnt];
	u16 swap_cnt = *swaps_vec;
	u16 *swaps = swaps_vec + 1;
	struct bcf_expr_ref *roc;
	u32 param_cnt, swap_vec_sz;

	if (swap_cnt > pm->vlen)
		return ERR_PTR(-EINVAL);

	swap_vec_sz = ((u32)swap_cnt + 1) * sizeof(u16);
	param_cnt = DIV_ROUND_UP_POW2(swap_vec_sz, 4);
	if (param_cnt != step->param_cnt)
		return ERR_PTR(-EINVAL);
	if (swap_vec_sz % 4 && swaps[swap_cnt] != 0)
		return ERR_PTR(-EINVAL);

	roc = clone_expr(st, pm);
	for (u32 i = 0; i < swap_cnt; i++) {
		u8 j = swaps[i];
		u8 k = swaps[i] >> 8;

		if (j >= roc->vlen || k >= roc->vlen)
			return ERR_PTR(-EINVAL);
		swap(roc->args[j], roc->args[k]);
	}
	return roc;
}

static int equiv_elim(struct bcf_checker_state *st, struct bcf_expr *premise,
		      u32 form)
{
	struct bcf_expr_ref *not_expr, *fact;
	u32 e0, e1;

	ENSURE(form == 0 || form == 1);

	e0 = premise->args[0];
	e1 = premise->args[1];
	if (form) {
		not_expr = build_bool_not(st, e1);
		CHECK_PTR(not_expr);
		e1 = not_expr->id;
		expr_id_get(st, e0);
	} else {
		not_expr = build_bool_not(st, e0);
		CHECK_PTR(not_expr);
		e0 = not_expr->id;
		expr_id_get(st, e1);
	}

	fact = build_disj_move(st, e0, e1);
	return set_step_fact(st, fact);
}

static int not_equiv_elim(struct bcf_checker_state *st,
			  struct bcf_expr *premise, u32 form)
{
	struct bcf_expr_ref *not_expr, *fact;
	u32 e0, e1;

	ENSURE(form == 0 || form == 1);

	e0 = premise->args[0];
	e1 = premise->args[1];
	if (form) {
		not_expr = build_bool_not(st, e0);
		CHECK_PTR(not_expr);
		e0 = not_expr->id;

		not_expr = build_bool_not(st, e1);
		CHECK_PTR(not_expr);
		e1 = not_expr->id;
	} else {
		expr_id_get(st, e0);
		expr_id_get(st, e1);
	}

	fact = build_disj_move(st, e0, e1);
	return set_step_fact(st, fact);
}

static int __cnf_equiv_pos(struct bcf_checker_state *st, u32 arg, u32 form,
			   bool xor)
{
	struct bcf_expr_ref *not_expr, *fact;
	struct bcf_expr *arg_expr;
	u8 code = xor ? (BCF_BOOL | BCF_XOR) : (BCF_BOOL | BPF_JEQ);
	u32 e0, e1, e2;

	ENSURE(form == 0 || form == 1);

	arg_expr = get_arg_expr(st, arg);
	CHECK_PTR(arg_expr);
	ENSURE(arg_expr->code == code);

	e0 = arg;
	if (!xor) {
		not_expr = build_bool_not(st, arg);
		CHECK_PTR(not_expr);
		e0 = not_expr->id;
	}

	e1 = arg_expr->args[0];
	e2 = arg_expr->args[1];
	if (form) {
		not_expr = build_bool_not(st, e2);
		CHECK_PTR(not_expr);
		e2 = not_expr->id;
	} else {
		not_expr = build_bool_not(st, e1);
		CHECK_PTR(not_expr);
		e1 = not_expr->id;
	}

	fact = build_disj_move(st, e0, e1, e2);
	return set_step_fact(st, fact);
}

static int cnf_equiv_pos(struct bcf_checker_state *st, u32 arg, u32 form)
{
	return __cnf_equiv_pos(st, arg, form, false);
}

static int cnf_xor_neg(struct bcf_checker_state *st, u32 arg, u32 form)
{
	return __cnf_equiv_pos(st, arg, form, true);
}

static int __cnf_equiv_neg(struct bcf_checker_state *st, u32 arg, u32 lit,
			   bool xor)
{
	u8 code = xor ? (BCF_BOOL | BCF_XOR) : (BCF_BOOL | BPF_JEQ);
	struct bcf_expr_ref *not_expr, *fact;
	struct bcf_expr *arg_expr;
	u32 e0, e1, e2;

	ENSURE(lit == 0 || lit == 1);

	arg_expr = get_arg_expr(st, arg);
	CHECK_PTR(arg_expr);
	ENSURE(arg_expr->code == code);

	e0 = arg;
	if (xor) { /* equiv_neg == xor_pos */
		not_expr = build_bool_not(st, arg);
		CHECK_PTR(not_expr);
		e0 = not_expr->id;
	}

	e1 = arg_expr->args[0];
	e2 = arg_expr->args[1];
	if (lit) {
		not_expr = build_bool_not(st, e1);
		CHECK_PTR(not_expr);
		e1 = not_expr->id;
		not_expr = build_bool_not(st, e2);
		CHECK_PTR(not_expr);
		e2 = not_expr->id;
	}
	fact = build_disj_move(st, e0, e1, e2);
	return set_step_fact(st, fact);
}

static int cnf_equiv_neg(struct bcf_checker_state *st, u32 arg, u32 lit)
{
	return __cnf_equiv_neg(st, arg, lit, false);
}

static int cnf_xor_pos(struct bcf_checker_state *st, u32 arg, u32 lit)
{
	return __cnf_equiv_neg(st, arg, lit, true);
}

static int apply_bool_rule(struct bcf_checker_state *st,
			   struct bcf_proof_step *step)
{
	DEFINE_JUMP_TABLE(BCF_BOOL_RULES);
	u16 rule = BCF_STEP_RULE(step->rule);
	u16 pm_cnt = step->premise_cnt;
	u16 param_cnt = step->param_cnt;
	struct bcf_expr *premise, *expr_buf, *arg_expr;
	struct bcf_expr_ref *fact, *not_expr;
	u32 premise_id;

	goto *checkers[rule];

RESOLUTION: /* (A ∨ l), (¬l ∨ B) ⊢ (A ∨ B) */
{
	ENSURE(pm_cnt >= 2 && param_cnt);
	return chain_resolution(st, step);
}

FACTORING: /* (A ∨ l ∨ l) ⊢ (A ∨ l) */
{
	ENSURE(pm_cnt == 1 && param_cnt >= 1);
	premise = get_premise(st, step, 0);
	ENSURE(is_bool_disj(premise->code));
	return factoring(st, premise, &step->args[1], param_cnt);
}

REORDERING: /* (l₁ ∨ ... ∨ lₙ) ⊢ (l_{π(1)} ∨ ... ∨ l_{π(n)}) */
{
	ENSURE(pm_cnt == 1);
	premise = get_premise(st, step, 0);
	if (!is_bool_disj(premise->code) || !param_cnt)
		return set_step_fact_id(st, get_premise_id(st, step, 0));

	/* Compute the reordered cluase. */
	fact = apply_reordering(st, premise, step);
	return set_step_fact(st, fact);
}

SPLIT: /* ⊢ A ∨ ¬A */
{
	struct bcf_expr_ref *not;
	u32 arg;

	ENSURE(!pm_cnt && param_cnt == 1);

	arg = step->args[0];
	arg_expr = get_bool_arg(st, arg);
	CHECK_PTR(arg_expr);

	not = build_bool_not_move(st, arg);
	CHECK_PTR(not);
	fact = build_disj_move(st, arg, not->id);
	return set_step_fact(st, fact);
}

EQ_RESOLVE: /* (A, A = B) ⊢ B */
{
	ENSURE(pm_cnt == 2 && !param_cnt);

	premise_id = get_premise_id(st, step, 0);
	premise = get_premise(st, step, 1);
	ENSURE(is_bool_eq(premise->code));
	ENSURE(expr_id_equiv(st, premise_id, premise->args[0]) == 1);
	return set_step_fact_id(st, premise->args[1]);
}

MODUS_PONENS: /* A, (A ⇒ B) ⊢ B */
{
	ENSURE(pm_cnt == 2 && !param_cnt);

	premise_id = get_premise_id(st, step, 0);
	premise = get_premise(st, step, 1);
	ENSURE(is_bool_implies(premise->code));
	ENSURE(expr_id_equiv(st, premise_id, premise->args[0]) == 1);
	return set_step_fact_id(st, premise->args[1]);
}

NOT_NOT_ELIM: /* ¬¬A ⊢ A */
{
	ENSURE(pm_cnt == 1 && !param_cnt);

	premise = get_premise(st, step, 0);
	ENSURE(is_bool_not(premise->code));
	premise = id_to_expr(st, premise->args[0]);
	ENSURE(is_bool_not(premise->code));
	return set_step_fact_id(st, premise->args[0]);
}

CONTRA: /* A, ¬A ⊢ ⊥ */
{
	ENSURE(pm_cnt == 2 && !param_cnt);

	premise_id = get_premise_id(st, step, 0);
	premise = get_premise(st, step, 1);
	ENSURE(is_bool_not(premise->code));
	ENSURE(expr_id_equiv(st, premise_id, premise->args[0]) == 1);
	return set_step_fact_id(st, st->false_expr);
}

AND_ELIM: /* (A ∧ B) ⊢ A */
{
	u32 clause;

	ENSURE(pm_cnt == 1 && param_cnt == 1);

	premise = get_premise(st, step, 0);
	clause = step->args[1];
	ENSURE(is_bool_conj(premise->code) && clause < premise->vlen);
	return set_step_fact_id(st, premise->args[clause]);
}

AND_INTRO: /* A, B ⊢ (A ∧ B) */
{
	u32 *clauses;

	ENSURE(pm_cnt && !param_cnt);

	if (pm_cnt == 1) {
		premise_id = get_premise_id(st, step, 0);
		return set_step_fact_id(st, premise_id);
	}

	expr_buf = get_expr_buf(st);
	expr_buf->code = BCF_BOOL | BCF_CONJ;
	expr_buf->vlen = pm_cnt;
	clauses = expr_buf->args;
	bcf_for_each_pm_id(clause, step, st) {
		*clauses++ = clause;
	}
	fact = clone_expr(st, expr_buf);
	return set_step_fact(st, fact);
}

NOT_OR_ELIM: /* ¬(A ∨ B) ⊢ ¬A */
{
	u32 lit; /* literal */

	ENSURE(pm_cnt == 1 && param_cnt == 1);

	premise = get_premise(st, step, 0);
	ENSURE(is_bool_not(premise->code));
	premise = id_to_expr(st, premise->args[0]);
	ENSURE(is_bool_disj(premise->code));

	lit = step->args[1];
	ENSURE(lit < premise->vlen);

	fact = build_bool_not(st, premise->args[lit]);
	return set_step_fact(st, fact);
}

IMPLIES_ELIM: /* (A ⇒ B) ⊢ ¬A ∨ B */
{
	struct bcf_expr_ref *not;

	ENSURE(pm_cnt == 1 && !param_cnt);

	premise = get_premise(st, step, 0);
	ENSURE(is_bool_implies(premise->code));
	premise_id = premise->args[1];
	not = build_bool_not(st, premise->args[0]);
	CHECK_PTR(not);
	expr_id_get(st, premise_id);
	fact = build_disj_move(st, not->id, premise_id);
	return set_step_fact(st, fact);
}

NOT_IMPLIES_ELIM: /* ¬(A ⇒ B) ⊢ A ∧ ¬B */
{
	u32 idx;

	ENSURE(pm_cnt == 1 && param_cnt == 1);

	idx = step->args[1];
	ENSURE(idx == 0 || idx == 1);

	premise = get_premise(st, step, 0);
	ENSURE(is_bool_not(premise->code));
	premise = id_to_expr(st, premise->args[0]);
	ENSURE(is_bool_implies(premise->code));

	if (idx == 0)
		return set_step_fact_id(st, premise->args[0]);

	fact = build_bool_not(st, premise->args[1]);
	return set_step_fact(st, fact);
}

EQUIV_ELIM: /* (A ⇔ B) ⊢ (¬A ∨ B) ∧ (A ∨ ¬B) */
{
	ENSURE(pm_cnt == 1 && param_cnt == 1);

	premise = get_premise(st, step, 0);
	ENSURE(is_bool_eq(premise->code));
	return equiv_elim(st, premise, step->args[1]);
}

NOT_EQUIV_ELIM: /* ¬(A ⇔ B) ⊢ (A ∨ B) ∧ (¬A ∨ ¬B) */
{
	ENSURE(pm_cnt == 1 && param_cnt == 1);

	premise = get_premise(st, step, 0);
	ENSURE(is_bool_not(premise->code));
	premise = id_to_expr(st, premise->args[0]);
	ENSURE(is_bool_eq(premise->code));
	return not_equiv_elim(st, premise, step->args[1]);
}

XOR_ELIM: /* (A ⊕ B) ⊢ (A ∨ B) ∧ (¬A ∨ ¬B) */
{
	ENSURE(pm_cnt == 1 && param_cnt == 1);

	premise = get_premise(st, step, 0);
	ENSURE(is_bool_xor(premise->code));
	return not_equiv_elim(st, premise, step->args[1]);
}

NOT_XOR_ELIM: /* ¬(A ⊕ B) ⊢ (A ∨ ¬B) ∧ (¬A ∨ B) */
{
	u32 lit;

	ENSURE(pm_cnt == 1 && param_cnt == 1);

	premise = get_premise(st, step, 0);
	ENSURE(is_bool_not(premise->code));
	premise = id_to_expr(st, premise->args[0]);
	ENSURE(is_bool_xor(premise->code));

	lit = step->args[1];
	ENSURE(lit == 0 || lit == 1);
	/* reverse lit to reuse equiv_elim */
	lit = lit ? 0 : 1;

	return equiv_elim(st, premise, step->args[1]);
}

ITE_ELIM: /* (C ? A : B) ⊢ (¬C ∨ A) ∧ (C ∨ B) */
{
	u32 lit, e0, e1;

	ENSURE(pm_cnt == 1 && param_cnt == 1);

	premise = get_premise(st, step, 0);
	ENSURE(is_ite_bool_cond(st, premise));

	lit = step->args[1];
	ENSURE(lit == 0 || lit == 1);
	if (lit) {
		/* C ∨ B */
		e0 = premise->args[0];
		e1 = premise->args[2];
		expr_id_get(st, e0);
		expr_id_get(st, e1);
	} else {
		/* ¬C ∨ A */
		not_expr = build_bool_not(st, premise->args[0]);
		CHECK_PTR(not_expr);
		e0 = not_expr->id;
		e1 = premise->args[1];
		expr_id_get(st, e1);
	}
	fact = build_disj_move(st, e0, e1);
	return set_step_fact(st, fact);
}

NOT_ITE_ELIM: /* ¬(C ? A : B) ⊢ (¬C ∨ ¬A) ∧ (C ∨ ¬B) */
{
	struct bcf_expr_ref *not_c, *not_a, *not_b;
	u32 lit, e0, e1;

	ENSURE(pm_cnt == 1 && param_cnt == 1);

	premise = get_premise(st, step, 0);
	ENSURE(is_bool_not(premise->code));
	premise = id_to_expr(st, premise->args[0]);
	ENSURE(is_ite_bool_cond(st, premise));

	lit = step->args[1];
	ENSURE(lit == 0 || lit == 1);

	if (lit) {
		/* C ∨ ¬B */
		e0 = premise->args[0];
		expr_id_get(st, e0);
		not_b = build_bool_not(st, premise->args[2]);
		CHECK_PTR(not_b);
		e1 = not_b->id;
	} else {
		/* ¬C ∨ ¬A */
		not_c = build_bool_not(st, premise->args[0]);
		CHECK_PTR(not_c);
		e0 = not_c->id;
		not_a = build_bool_not(st, premise->args[1]);
		CHECK_PTR(not_a);
		e1 = not_a->id;
	}

	fact = build_disj_move(st, e0, e1);
	return set_step_fact(st, fact);
}

NOT_AND: /* ¬(A ∧ B) ⊢ (¬A ∨ ¬B) */
{
	u32 *args;

	ENSURE(pm_cnt == 1 && param_cnt);

	premise = get_premise(st, step, 0);
	ENSURE(is_bool_not(premise->code));
	premise = id_to_expr(st, premise->args[0]);
	ENSURE(is_bool_conj(premise->code));

	fact = alloc_expr(st, premise->vlen);
	CHECK_PTR(fact);
	fact->code = BCF_BOOL | BCF_DISJ;
	fact->vlen = premise->vlen;
	fact->params = 0;
	args = fact->args;
	bcf_for_each_arg(arg, premise) {
		not_expr = build_bool_not(st, arg);
		CHECK_PTR(not_expr);
		*args++ = not_expr->id;
	}
	return set_step_fact(st, fact);
}

CNF_AND_POS: /* ¬(A ∧ B) ∨ A */
{
	u32 lit;

	ENSURE(!pm_cnt && param_cnt == 2);

	arg_expr = get_arg_expr(st, step->args[0]);
	CHECK_PTR(arg_expr);
	ENSURE(is_bool_conj(arg_expr->code));

	lit = step->args[1];
	ENSURE(lit < arg_expr->vlen);

	not_expr = build_bool_not(st, step->args[0]);
	CHECK_PTR(not_expr);
	expr_id_get(st, arg_expr->args[lit]);

	fact = build_disj_move(st, not_expr->id, arg_expr->args[lit]);
	return set_step_fact(st, fact);
}

CNF_AND_NEG: /* (A ∧ B) ∨ ¬A ∨ ¬B */
{
	u32 *args;

	ENSURE(!pm_cnt && param_cnt == 1);

	arg_expr = get_arg_expr(st, step->args[0]);
	CHECK_PTR(arg_expr);
	ENSURE(is_bool_conj(arg_expr->code) && arg_expr->vlen < U8_MAX);

	fact = alloc_expr(st, arg_expr->vlen + 1);
	CHECK_PTR(fact);
	fact->code = BCF_BOOL | BCF_DISJ;
	fact->vlen = arg_expr->vlen + 1;
	fact->params = 0;
	args = fact->args;
	*args++ = step->args[0];
	bcf_for_each_arg(arg, arg_expr) {
		not_expr = build_bool_not(st, arg);
		CHECK_PTR(not_expr);
		*args++ = not_expr->id;
	}
	return set_step_fact(st, fact);
}

CNF_OR_POS: /* ¬(A ∨ B) ∨ A ∨ B */
{
	u32 *args;

	ENSURE(!pm_cnt && param_cnt == 1);

	arg_expr = get_arg_expr(st, step->args[0]);
	CHECK_PTR(arg_expr);
	ENSURE(is_bool_disj(arg_expr->code) && arg_expr->vlen < U8_MAX);

	not_expr = build_bool_not(st, step->args[0]);
	CHECK_PTR(not_expr);

	fact = alloc_expr(st, arg_expr->vlen + 1);
	CHECK_PTR(fact);
	fact->code = BCF_BOOL | BCF_DISJ;
	fact->vlen = arg_expr->vlen + 1;
	fact->params = 0;
	args = fact->args;
	*args++ = not_expr->id;
	bcf_for_each_arg(arg, arg_expr) {
		expr_id_get(st, arg);
		*args++ = arg;
	}
	return set_step_fact(st, fact);
}

CNF_OR_NEG: /* (A ∨ B) ∨ ¬A */
{
	u32 lit;

	ENSURE(!pm_cnt && param_cnt == 2);

	arg_expr = get_arg_expr(st, step->args[0]);
	CHECK_PTR(arg_expr);
	ENSURE(is_bool_disj(arg_expr->code));
	lit = step->args[1];
	ENSURE(lit < arg_expr->vlen);

	not_expr = build_bool_not(st, arg_expr->args[lit]);
	CHECK_PTR(not_expr);
	fact = build_disj_move(st, step->args[0], not_expr->id);
	return set_step_fact(st, fact);
}

CNF_IMPLIES_POS: /* (A ⇒ B) ∨ ¬A ∨ B */
{
	struct bcf_expr_ref *not_term;

	ENSURE(!pm_cnt && param_cnt == 1);

	arg_expr = get_arg_expr(st, step->args[0]);
	CHECK_PTR(arg_expr);
	ENSURE(is_bool_implies(arg_expr->code));

	not_expr = build_bool_not(st, step->args[0]);
	CHECK_PTR(not_expr);
	not_term = build_bool_not(st, arg_expr->args[0]);
	CHECK_PTR(not_term);

	fact = build_disj_move(st, not_expr->id, not_term->id,
			       arg_expr->args[1]);
	return set_step_fact(st, fact);
}

CNF_IMPLIES_NEG: /* (A ⇒ B) ∨ (A ∧ ¬B) */
{
	u32 lit, e0, e1;

	ENSURE(!pm_cnt && param_cnt == 2);

	arg_expr = get_arg_expr(st, step->args[0]);
	CHECK_PTR(arg_expr);
	ENSURE(is_bool_implies(arg_expr->code));
	lit = step->args[1];
	ENSURE(lit == 0 || lit == 1);

	e0 = step->args[0];
	e1 = arg_expr->args[0];
	if (lit) {
		not_expr = build_bool_not(st, arg_expr->args[1]);
		CHECK_PTR(not_expr);
		e1 = not_expr->id;
	}
	fact = build_disj_move(st, e0, e1);
	return set_step_fact(st, fact);
}

CNF_EQUIV_POS: /* ¬(A ⇔ B) ∨ ¬A ∨ B */
{
	ENSURE(!pm_cnt && param_cnt == 2);
	return cnf_equiv_pos(st, step->args[0], step->args[1]);
}

CNF_EQUIV_NEG: /* (A ⇔ B) ∨ A ∨ B */
{
	ENSURE(!pm_cnt && param_cnt == 2);
	return cnf_equiv_neg(st, step->args[0], step->args[1]);
}

CNF_XOR_POS: /* ¬(A ⊕ B) ∨ ¬A ∨ B */
{
	ENSURE(!pm_cnt && param_cnt == 2);
	return cnf_xor_pos(st, step->args[0], step->args[1]);
}

CNF_XOR_NEG: /* (A ⊕ B) ∨ A ∨ B */
{
	ENSURE(!pm_cnt && param_cnt == 2);
	return cnf_xor_neg(st, step->args[0], step->args[1]);
}

CNF_ITE_POS: /* ¬(C ? A : B) ∨ ¬C ∨ A*/
{
	/* Produces a disjunction of three terms based on the value of 'lit':
	 * - lit == 0: ¬(C ? A : B) ∨ ¬C ∨ A
	 * - lit == 1: ¬(C ? A : B) ∨ C ∨ B
	 * - lit == 2: ¬(C ? A : B) ∨ A ∨ B
	 */
	u32 lit;
	u32 e0, e1, e2;

	ENSURE(!pm_cnt && param_cnt == 2);

	arg_expr = get_arg_expr(st, step->args[0]);
	CHECK_PTR(arg_expr);
	ENSURE(is_ite_bool_cond(st, arg_expr));
	lit = step->args[1];

	e0 = step->args[0];
	not_expr = build_bool_not(st, e0);
	CHECK_PTR(not_expr);
	e0 = not_expr->id;

	switch (lit) {
	case 0:
		e1 = arg_expr->args[0];
		e2 = arg_expr->args[1];
		not_expr = build_bool_not(st, e1);
		CHECK_PTR(not_expr);
		e1 = not_expr->id;
		break;
	case 1:
		e1 = arg_expr->args[0];
		e2 = arg_expr->args[2];
		break;
	case 2:
		e1 = arg_expr->args[1];
		e2 = arg_expr->args[2];
		break;
	default:
		return -EINVAL;
	}

	fact = build_disj_move(st, e0, e1, e2);
	return set_step_fact(st, fact);
}

CNF_ITE_NEG: /* (C ? A : B) ∨ ¬C ∨ ¬A */
{
	/* Produces a disjunction of three terms based on the value of 'lit':
	 * - lit == 0: (C ? A : B) ∨ ¬C ∨ ¬A
	 * - lit == 1: (C ? A : B) ∨ C ∨ ¬B
	 * - lit == 2: (C ? A : B) ∨ ¬A ∨ ¬B
	 */
	u32 lit;
	u32 e0, e1, e2;

	ENSURE(!pm_cnt && param_cnt == 2);

	arg_expr = get_arg_expr(st, step->args[0]);
	CHECK_PTR(arg_expr);
	ENSURE(is_ite_bool_cond(st, arg_expr));
	lit = step->args[1];

	e0 = step->args[0];

	switch (lit) {
	case 0:
		e1 = arg_expr->args[0];
		not_expr = build_bool_not(st, e1);
		CHECK_PTR(not_expr);
		e1 = not_expr->id;

		e2 = arg_expr->args[1];
		not_expr = build_bool_not(st, e2);
		CHECK_PTR(not_expr);
		e2 = not_expr->id;
		break;
	case 1:
		e1 = arg_expr->args[0];
		e2 = arg_expr->args[2];
		not_expr = build_bool_not(st, e2);
		CHECK_PTR(not_expr);
		e2 = not_expr->id;
		break;
	case 2:
		e1 = arg_expr->args[1];
		e2 = arg_expr->args[2];
		not_expr = build_bool_not(st, e1);
		CHECK_PTR(not_expr);
		e1 = not_expr->id;
		not_expr = build_bool_not(st, e2);
		CHECK_PTR(not_expr);
		e2 = not_expr->id;
		break;
	default:
		return -EINVAL;
	}

	fact = build_disj_move(st, e0, e1, e2);
	return set_step_fact(st, fact);
}

ITE_EQ: /* (C ? (C ? A : B) = A : (C ? A : B) = B) */
{
	struct bcf_expr_ref *eq_expr;
	u32 c, t0, t1, e1, e2;

	ENSURE(!pm_cnt && param_cnt == 1);

	arg_expr = get_arg_expr(st, step->args[0]);
	CHECK_PTR(arg_expr);
	ENSURE(is_ite_bool_cond(st, arg_expr));

	c = step->args[0];
	t0 = arg_expr->args[1];
	t1 = arg_expr->args[2];

	eq_expr = build_bool_eq_move(st, c, t0);
	CHECK_PTR(eq_expr);
	e1 = eq_expr->id;

	eq_expr = build_bool_eq_move(st, c, t1);
	CHECK_PTR(eq_expr);
	e2 = eq_expr->id;

	fact = build_bool_ite_move(st, arg_expr->args[0], e1, e2);
	return set_step_fact(st, fact);
}

bad_rule:
	WARN_ONCE(1, "Unknown boolean rule: %u", BCF_STEP_RULE(step->rule));
	return -EFAULT;
}

static bool is_bool_conj2(struct bcf_checker_state *st, u32 e_id)
{
	struct bcf_expr *expr = id_to_expr(st, e_id);

	return is_bool_conj(expr->code) && expr->vlen == 2;
}

/* Check bitblast bv_ult
 * bb_ult: Validate canonical bit-blast for unsigned less-than/less-equal.
 * Structure enforced for bits i = vlen-1..1:
 *   res = ((lhs[i] == rhs[i]) ∧ rest) ∨ ((¬lhs[i]) ∧ rhs[i]),
 * descending with rest at each step.
 * Base (i == 0, strict <): res = ((¬lhs[0]) ∧ rhs[0]).
 * For ≤ (eq=true): at the base, require a disjunction with equality bit:
 *   res = ((¬lhs[0]) ∧ rhs[0]) ∨ (lhs[0] == rhs[0]).
 */
static int bb_ult(struct bcf_checker_state *st, struct bcf_expr *res, u32 *lhs,
		  u32 *rhs, u8 vlen, bool eq)
{
	struct bcf_expr *l, *r;

	if (WARN_ON_ONCE(!vlen))
		return -EFAULT;

	/* a < b iff ( a[i] <-> b[i] AND a[i-1:0] < b[i-1:0]) OR (~a[i] AND b[i]) */
	for (u32 i = vlen - 1; i > 0; i--) {
		ENSURE(is_bool_disj(res->code) && res->vlen == 2);
		ENSURE(is_bool_conj2(st, res->args[0]));
		ENSURE(is_bool_conj2(st, res->args[1]));

		r = id_to_expr(st, res->args[1]);
		ENSURE(is_bool_not_of(st, r->args[0], lhs[i]));
		ENSURE(r->args[1] == rhs[i]);

		l = id_to_expr(st, res->args[0]);
		ENSURE(is_bool_eq_of(st, l->args[0], lhs[i], rhs[i]));
		res = id_to_expr(st, l->args[1]);
	}

	if (eq) {
		ENSURE(is_bool_disj(res->code) && res->vlen == 2);
		ENSURE(is_bool_eq_of(st, res->args[1], lhs[0], rhs[0]));
		res = id_to_expr(st, res->args[0]);
	}

	ENSURE(is_bool_conj(res->code) && res->vlen == 2);
	ENSURE(res->args[1] == rhs[0]);
	ENSURE(is_bool_not_of(st, res->args[0], lhs[0]));
	return 0;
}

/* Check bitblast bv_slt
 * bb_slt: Validate canonical bit-blast for signed less-than/less-equal.
 * MSB index s = vlen-1. Enforce:
 *   res = ((lhs[s] == rhs[s]) ∧ rest) ∨ (lhs[s] ∧ ¬rhs[s]),
 * where 'rest' is the unsigned comparator over lower bits (s-1..0),
 * with eq propagated for ≤.
 */
static int bb_slt(struct bcf_checker_state *st, struct bcf_expr *res, u32 *lhs,
		  u32 *rhs, u32 vlen, bool eq)
{
	struct bcf_expr *sign_same, *neg_lhs;
	u32 sbit;

	ENSURE(vlen > 1);
	sbit = vlen - 1;

	ENSURE(is_bool_disj(res->code) && res->vlen == 2);
	ENSURE(is_bool_conj2(st, res->args[0]));
	ENSURE(is_bool_conj2(st, res->args[1]));

	neg_lhs = id_to_expr(st, res->args[1]);
	ENSURE(neg_lhs->args[0] == lhs[sbit]);
	ENSURE(is_bool_not_of(st, neg_lhs->args[1], rhs[sbit]));

	sign_same = id_to_expr(st, res->args[0]);
	ENSURE(is_bool_eq_of(st, sign_same->args[0], lhs[sbit], rhs[sbit]));
	/* recurse into lower-bit comparator guarded by equal sign-bit */
	res = id_to_expr(st, sign_same->args[1]);
	return bb_ult(st, res, lhs, rhs, vlen - 1, eq);
}

/* check_bb_atom: Validate bit-blasted boolean atoms (comparisons).
 * Inputs (lhs, rhs) must already be bit-blasted vectors (FROM_BOOL) of equal
 * width. Supported ops:
 *   - JEQ: conjunction over all bits of (lhs[i] == rhs[i])
 *   - JLT/JLE: unsigned comparator via bb_ult (eq=false/true)
 *   - JSLT/JSLE: signed comparator via bb_slt (eq=false/true)
 * Any other opcode is rejected here (may be rewritten earlier).
 */
static int check_bb_atom(struct bcf_checker_state *st, struct bcf_expr *atom,
			 struct bcf_expr *bbt)
{
	u32 *lbits, *rbits, vlen, i;
	u8 op = BCF_OP(atom->code);
	bool eq = false;

	switch (op) {
	case BPF_JLE:
	case BPF_JSLE:
	case BPF_JEQ:
		eq = true;
		fallthrough;
	case BPF_JLT:
	case BPF_JSLT: {
		struct bcf_expr *lhs, *rhs;

		lhs = id_to_expr(st, atom->args[0]);
		rhs = id_to_expr(st, atom->args[1]);
		/* Must be already bitblasted term. */
		ENSURE(is_bv_from_bool(lhs->code));
		ENSURE(is_bv_from_bool(rhs->code));

		vlen = lhs->vlen;
		lbits = lhs->args;
		rbits = rhs->args;
		break;
	}
	default:
		/* Other ops are converted, e.g., `a ugt b` => `b ult a`,
		 * or the expr is not a bv predicate.
		 */
		return -EINVAL;
	}

	if (op == BPF_JEQ) {
		ENSURE(is_bool_conj(bbt->code) && bbt->vlen == vlen);
		for (i = 0; i < bbt->vlen; i++)
			ENSURE(is_bool_eq_of(st, bbt->args[i], lbits[i],
					     rbits[i]));

		return 0;
	}

	if (op == BPF_JLT || op == BPF_JLE)
		return bb_ult(st, bbt, lbits, rbits, vlen, eq);

	/* BPF_JSLT || BPF_JSLE */
	return bb_slt(st, bbt, lbits, rbits, vlen, eq);
}

static int bb_bitwise_op(struct bcf_checker_state *st, struct bcf_expr *term,
			 struct bcf_expr *bbt, u8 op)
{
	struct bcf_expr *sub, *bit;
	u32 bit_id;

	for (u32 i = 0; i < bbt->vlen; i++) {
		bit_id = bbt->args[i];
		bit = id_to_expr(st, bit_id);
		for (u32 j = term->vlen - 1; j > 0; j--) {
			ENSURE(BCF_OP(bit->code) == op && bit->vlen == 2);
			sub = id_to_expr(st, term->args[j]);
			ENSURE(bit->args[1] == sub->args[i]);

			bit_id = bit->args[0];
			bit = id_to_expr(st, bit_id);
		}
		sub = id_to_expr(st, term->args[0]);
		ENSURE(bit_id == sub->args[i]);
	}
	return 0;
}

/* Check if `res` faithfully represents `a + b` */
static int check_ripple_carry_adder(struct bcf_checker_state *st, u32 vlen,
				    u32 *a, u32 *b, u32 *res, bool init_carry)
{
	struct bcf_expr *sum, *carry, *sub;
	u32 pre_carry;

	for (u32 i = 0; i < vlen; i++) {
		sum = id_to_expr(st, res[i]);
		ENSURE(is_bool_xor(sum->code) && sum->vlen == 2);

		ENSURE(is_bool_xor_of(st, sum->args[0], a[i], b[i]));

		carry = id_to_expr(st, sum->args[1]);
		if (i == 0) {
			ENSURE(init_carry ? is_true(carry) : is_false(carry));
			continue;
		}

		/* check carry */
		ENSURE(is_bool_disj(carry->code) && carry->vlen == 2);

		sub = id_to_expr(st, carry->args[0]);
		ENSURE(is_bool_conj(sub->code) && sub->vlen == 2);
		ENSURE(sub->args[0] == a[i - 1] && sub->args[1] == b[i - 1]);

		sub = id_to_expr(st, carry->args[1]);
		ENSURE(is_bool_conj(sub->code) && sub->vlen == 2);
		ENSURE(is_bool_xor_of(st, sub->args[0], a[i - 1], b[i - 1]));

		pre_carry = id_to_expr(st, res[i - 1])->args[1];
		ENSURE(sub->args[1] == pre_carry);
	}

	return 0;
}

static int extract_pre_sum(struct bcf_checker_state *st, u32 vlen, u32 *sum,
			   u32 *pre_sum)
{
	struct bcf_expr *sub;

	for (u32 i = 0; i < vlen; i++) {
		sub = id_to_expr(st, sum[i]);
		ENSURE(sub->vlen);
		sub = id_to_expr(st, sub->args[0]);
		ENSURE(sub->vlen);
		pre_sum[i] = sub->args[0];
	}
	return 0;
}

static int extract_pre_adder(struct bcf_checker_state *st, u32 vlen, u32 *sum,
			     u32 *pre_adder)
{
	struct bcf_expr *sub;

	for (u32 i = 0; i < vlen; i++) {
		sub = id_to_expr(st, sum[i]);
		ENSURE(sub->vlen);
		sub = id_to_expr(st, sub->args[0]);
		ENSURE(sub->vlen > 1);
		pre_adder[i] = sub->args[1];
	}
	return 0;
}

/* Validate the outer guard and fill semantics for bit-blasted shifts.
 * RHS bits must be ITE(cond, stage_out[i], fill), where:
 *   - cond = (b < bit_sz) encoded as a bit-blasted unsigned compare,
 *   - stage_out[i] is the per-stage barrel-shift network output (collected into
 *     res[i] = then-branch),
 *   - fill is False (logical) or MSB(a) (arithmetic) for right shifts, and
 *     False for left shifts.
 * The same cond node must be shared by all bits to ensure a single guard.
 */
static int bb_shift_limit(struct bcf_checker_state *st, struct bcf_expr *term,
			  struct bcf_expr *bbt, bool logic_shift, u32 *res)
{
	struct bcf_expr *ite, *cond, *b, *bit, *a;
	u32 *bb_size, checked_cond;
	u64 bit_sz = bv_size(term);
	int err;

	a = id_to_expr(st, term->args[0]);
	b = id_to_expr(st, term->args[1]);
	ite = id_to_expr(st, bbt->args[0]);
	ENSURE(is_bool_ite(ite->code));

	/* The top level of bbt must assert that each bit is either a result
	 * of shift, or a zero if b is bigger then the bit sz:
	 * 	b < bit_sz ? res : 0
	 */
	cond = id_to_expr(st, ite->args[0]);
	/* Bitblasted representation of bit_sz. */
	bb_size = get_expr_buf(st)->args;
	for (u32 i = 0; i < b->vlen; i++) {
		if (i < 64 && bit_sz & (1ULL << i))
			bb_size[i] = st->true_expr;
		else
			bb_size[i] = st->false_expr;
	}
	err = bb_ult(st, cond, b->args, bb_size, b->vlen, false);
	if (err)
		return err;

	checked_cond = ite->args[0];
	bcf_for_each_arg_expr(i, bit, bbt, st) {
		ENSURE(is_bool_ite(bit->code) && bit->args[0] == checked_cond);
		if (logic_shift)
			ENSURE(is_false(id_to_expr(st, bit->args[2])));
		else
			/* must be the sign bit */
			ENSURE(bit->args[2] == a->args[a->vlen - 1]);
		res[i] = bit->args[1];
	}

	return 0;
}

/* Validate right shifts (logical if logic_shift=true, arithmetic otherwise)
 * using a staged barrel shifter peeled from the guarded RHS.
 * For stages i = floor(log2(bit_sz)) .. 0 with threshold = 1 << i:
 *   - For in-range positions (j + threshold < width):
 *       Each bit must be ITE(!b[i], keep, shift), with
 *         keep  = previous_stage[j],
 *         shift = previous_stage[j + threshold].
 *   - For overflow positions (j + threshold >= width):
 *       Each bit must be ITE(b[i], fill, keep), with
 *         fill = False (logical) or MSB(a) (arithmetic),
 *         keep = previous_stage[j].
 * After peeling all stages, the remaining vector must equal a’s bits.
 */
static int bb_rsh(struct bcf_checker_state *st, struct bcf_expr *term,
		  struct bcf_expr *bbt, bool logic_shift)
{
	u64 bit_sz = bv_size(term);
	u32 bit_limit = order_base_2(bit_sz);
	struct bcf_expr *a, *b, *bit;
	u32 *res, *pre_res;
	u32 arg_buf[U8_MAX];
	int err;

	res = arg_buf;
	err = bb_shift_limit(st, term, bbt, logic_shift, res);
	if (err)
		return err;

	a = id_to_expr(st, term->args[0]);
	b = id_to_expr(st, term->args[1]);
	pre_res = get_expr_buf(st)->args;
	for (int i = bit_limit - 1; i >= 0; i++) {
		u64 threshold = 1 << i;

		for (int j = a->vlen - 1; j >= 0; j--) {
			u32 shift_bit = b->args[i];

			bit = id_to_expr(st, res[j]);
			ENSURE(is_bool_ite(bit->code));

			if (j + threshold >= a->vlen) {
				u32 sign_bit = a->args[a->vlen - 1];
				u32 arg1 = bit->args[1];
				struct bcf_expr *sub;

				ENSURE(bit->args[0] == shift_bit);
				sub = id_to_expr(st, arg1);
				ENSURE(logic_shift ? is_false(sub) :
						     arg1 == sign_bit);

				pre_res[j] = bit->args[2];
			} else {
				ENSURE(is_bool_not_of(st, bit->args[0],
						      shift_bit));
				ENSURE(bit->args[2] == pre_res[j + threshold]);
				pre_res[j] = bit->args[1];
			}
		}

		res = pre_res;
	}
	ENSURE(memcmp(res, a->args, sizeof(u32) * a->vlen) == 0);
	return 0;
}

static int check_bb_term(struct bcf_checker_state *st, u32 term_id, u32 bbt_id)
{
#define BB_TERM_CHECKER(_bv, ty_name, op, op_name, _arity) \
	[op >> 3] = &&bb_##ty_name##_##op_name,
	static const void *const bb_term_table[32] __annotate_jump_table = {
		[0 ... 31] = &&not_supp_bb_term, BCF_BV_OP(BB_TERM_CHECKER)
	};
#undef BB_TERM_CHECKER
	struct bcf_expr *term = id_to_expr(st, term_id);
	struct bcf_expr *bbt = id_to_expr(st, bbt_id);
	struct bcf_expr *sub, *bit;
	u32 arg_buf[U8_MAX];
	int err;

	ENSURE(is_bv_from_bool(bbt->code));
	if (expr_arg_is_id(term->code)) {
		bcf_for_each_arg_expr(i, sub, term, st) {
			if (i == 0 && is_bv_ite(term->code)) {
				ENSURE(is_bool(sub->code) ||
				       is_bv_from_bool(sub->code));
				continue;
			}
			ENSURE(is_bv_from_bool(sub->code));
		}
	}

	goto *bb_term_table[BCF_OP(term->code) >> 3];

bb_bv_var: {
	for (u32 i = 0; i < bbt->vlen; i++)
		ENSURE(is_bitof(st, bbt->args[i], i, term_id));
	return 0;
}

bb_bv_val: {
	u64 val = bv_val(term);

	bcf_for_each_arg_expr(i, bit, bbt, st)
		ENSURE(val & (1ULL << i) ? is_true(bit) : is_false(bit));
	return 0;
}

bb_bv_not: {
	for (u32 i = 0; i < bbt->vlen; i++)
		ENSURE(is_bool_not_of(st, bbt->args[i], term->args[i]));
	return 0;
}

/* Arith ops */
bb_bv_neg: {
	/* Validate negation as two's-complement addition: add(~a, 0, carry_in=true).
	 * From the output sum bits (bbt->args):
	 *   - pre_sum := first XOR-input vector extracted per bit (extract_pre_sum),
	 *               must equal bitwise-NOT of a’s bits.
	 *   - adder   := second XOR-input vector, must be all-false (zero).
	 *   - Then check sum is a ripple-carry add of (pre_sum, adder)
	 *     with initial carry true (check_ripple_carry_adder).
	 */
	u32 vlen = bbt->vlen;
	u32 *pre_sum, *adder;

	sub = id_to_expr(st, term->args[0]);
	pre_sum = get_expr_buf(st)->args;
	err = extract_pre_sum(st, vlen, bbt->args, pre_sum);
	adder = arg_buf;
	err = err ?: extract_pre_adder(st, vlen, bbt->args, adder);
	if (err)
		return err;
	for (u32 i = 0; i < vlen; i++) {
		ENSURE(is_bool_not_of(st, pre_sum[i], sub->args[i]));
		ENSURE(is_false(id_to_expr(st, adder[i])));
	}

	err = check_ripple_carry_adder(st, vlen, pre_sum, adder, bbt->args,
				       true);
	return err;
}

bb_bv_add: {
	/* Validate multi-operand addition via staged ripple-carry “peeling”.
	 * Let result R = a0 + a1 + ... + an. Start with sum := R’s bits.
	 * For k = n..1:
	 *   - pre_sum := first XOR-input vector extracted from sum[i]
	 *               (extract_pre_sum).
	 *   - adder   := ak’s bit-vector.
	 *   - Check sum is a ripple-carry add of (pre_sum, adder)
	 *     with initial carry false (check_ripple_carry_adder).
	 *   - Set sum := pre_sum and continue.
	 * Finally, require sum == a0’s bit-vector (exact bitwise identity).
	 */
	u32 vlen = bbt->vlen;
	u32 *pre_sum = arg_buf, *sum;
	struct bcf_expr *adder;

	sum = st->expr_buf.args;
	memcpy(sum, bbt->args, sizeof(u32) * bbt->vlen);

	for (u32 i = term->vlen - 1; i > 0; i--) {
		adder = id_to_expr(st, term->args[i]);
		err = extract_pre_sum(st, vlen, sum, pre_sum);
		if (err)
			return err;
		err = check_ripple_carry_adder(st, vlen, pre_sum, adder->args,
					       sum, false);
		if (err)
			return err;

		swap(sum, pre_sum);
	}
	adder = id_to_expr(st, term->args[0]);
	ENSURE(memcmp(adder->args, sum, sizeof(u32) * vlen) == 0);
	return 0;
}

bb_bv_sub: {
	/* Validate subtraction as two's-complement transform: a - b == add(a, ~b, 1).
	 * From the output sum bits:
	 *   - pre_adder := second XOR-input vector per bit (extract_pre_adder),
	 *                 must equal bitwise-NOT of b’s bits.
	 *   - Then check sum is a ripple-carry add of (a, pre_adder)
	 *     with initial carry true (check_ripple_carry_adder).
	 */
	u32 *pre_adder, vlen = bbt->vlen;
	u32 *sum;

	sum = bbt->args;
	pre_adder = get_expr_buf(st)->args;
	err = extract_pre_adder(st, vlen, sum, pre_adder);
	if (err)
		return err;
	sub = id_to_expr(st, term->args[1]);
	for (u32 i = 0; i < vlen; i++)
		ENSURE(is_bool_not_of(st, pre_adder[i], sub->args[i]));

	sub = id_to_expr(st, term->args[0]);
	err = check_ripple_carry_adder(st, vlen, sub->args, pre_adder, sum,
				       true);
	return err;
}

/* Bitwise ops */
bb_bv_and:
	return bb_bitwise_op(st, term, bbt, BPF_AND);

bb_bv_or:
	return bb_bitwise_op(st, term, bbt, BPF_OR);

bb_bv_xor:
	return bb_bitwise_op(st, term, bbt, BPF_XOR);

bb_bv_lsh: {
	/* Validate left shift via staged barrel shifter peeled from the guarded RHS.
	 * For stages i = floor(log2(bit_sz)) .. 0 with threshold = 1 << i:
	 *   Each bit must be ITE(b[i], inject, keep), with
	 *     inject = False if j < threshold, else previous_stage[j - threshold],
	 *     keep   = previous_stage[j].
	 * After peeling all stages, the remaining vector must equal a’s bits.
	 */
	u64 bit_sz = bv_size(term);
	u32 bit_limit = order_base_2(bit_sz);
	struct bcf_expr *a, *b;
	u32 *res, *pre_res;

	ENSURE(bit_limit <= 64);

	res = arg_buf;
	err = bb_shift_limit(st, term, bbt, true, res);
	if (err)
		return err;

	/* Barrel shifter check. */
	a = id_to_expr(st, term->args[0]);
	b = id_to_expr(st, term->args[1]);
	pre_res = get_expr_buf(st)->args;
	for (int i = bit_limit - 1; i >= 0; i++) {
		u64 threshold = 1 << i;

		for (u32 j = 0; j < a->vlen; j++) {
			bit = id_to_expr(st, res[j]);
			ENSURE(is_bool_ite(bit->code));
			ENSURE(bit->args[0] == b->args[i]);

			if (j < threshold)
				ENSURE(is_false(id_to_expr(st, bit->args[1])));
			else
				ENSURE(bit->args[1] == pre_res[j - threshold]);

			pre_res[j] = bit->args[2];
		}

		res = pre_res;
	}
	ENSURE(memcmp(res, a->args, sizeof(u32) * a->vlen) == 0);
	return 0;
}

bb_bv_rsh: {
	return bb_rsh(st, term, bbt, true);
}

bb_bv_arsh: {
	return bb_rsh(st, term, bbt, false);
}

/* BV ops */
bb_bv_concat: {
	u32 base = 0;

	for (int i = term->vlen - 1; i >= 0; i--) {
		sub = id_to_expr(st, term->args[i]);
		for (int j = 0; j < sub->vlen; j++)
			ENSURE(bbt->args[base + j] == sub->args[j]);
		base += sub->vlen;
	}
	return 0;
}

bb_bv_extract: {
	u32 high = BCF_EXTRACT_START(term->params);
	u32 low = BCF_EXTRACT_END(term->params);

	sub = id_to_expr(st, term->args[0]);
	for (u32 i = low, j = 0; i <= high; i++, j++)
		ENSURE(bbt->args[j] == sub->args[i]);
	return 0;
}

bb_bv_sign_extend: {
	u32 ext_sz = BCF_EXT_LEN(term->params);
	u32 sign_bit;

	sub = id_to_expr(st, term->args[0]);
	for (u32 i = 0; i < sub->vlen; i++)
		ENSURE(sub->args[i] == bbt->args[i]);

	sign_bit = sub->args[sub->vlen - 1];
	for (u32 i = sub->vlen, j = 0; j < ext_sz; j++, i++)
		ENSURE(bbt->args[i] == sign_bit);
	return 0;
}

bb_bv_ite: {
	struct bcf_expr *then, *el;
	u32 cond;

	cond = term->args[0];
	then = id_to_expr(st, term->args[1]);
	el = id_to_expr(st, term->args[2]);
	for (u32 i = 0; i < bbt->vlen; i++) {
		/* Each bit must be: (!cond or then[i]) and (cond or el[i])*/
		sub = id_to_expr(st, bbt->args[i]);
		ENSURE(is_bool_conj2(st, bbt->args[i]));

		ENSURE(is_bool_disj_of(st, sub->args[1], cond, el->args[i]));

		sub = id_to_expr(st, sub->args[0]);
		ENSURE(is_bool_disj(sub->code) && sub->vlen == 2);
		ENSURE(is_bool_not_of(st, sub->args[0], cond));
		ENSURE(sub->args[1] == then->args[i]);
	}
	return 0;
}

/* Skip non-linear arith */
bb_bv_mul:
bb_bv_div:
bb_bv_sdiv:
bb_bv_mod:
bb_bv_smod:
	return -ENOTSUPP;

/* Should be rewritten */
bb_bv_repeat:
bb_bv_zero_extend:
/* Not bitblast candidates. */
bb_bv_from_bool:
bb_bv_bvsize:
	return -EINVAL;
not_supp_bb_term:
	return -EFAULT;
}

static int apply_bv_rule(struct bcf_checker_state *st,
			 struct bcf_proof_step *step)
{
	DEFINE_JUMP_TABLE(BCF_BV_RULES);
	u16 premise_cnt = step->premise_cnt;
	u16 param_cnt = step->param_cnt;
	struct bcf_expr *premise;
	struct bcf_expr_ref *fact;
	int err;

	goto *checkers[BCF_STEP_RULE(step->rule)];

BITBLAST: { /* Lowering bv term to bitblasted term (boolean circuit) */
	struct bcf_expr *bbt_eq, *bv, *bbt;

	ENSURE(!premise_cnt && param_cnt == 1);

	/* bbt_eq: must be bv = bbt, where
	 * - bv: bitvector term or atom (e.g. (+ bv0 bv1), (> bv0 bv1))
	 * - bbt: bitblasted form (bv_from_bool ...)
	 */
	bbt_eq = get_arg_expr(st, step->args[0]);
	CHECK_PTR(bbt_eq);
	ENSURE(is_bool_eq(bbt_eq->code));

	bv = id_to_expr(st, bbt_eq->args[0]);
	bbt = id_to_expr(st, bbt_eq->args[1]);
	if (is_bv(bv->code))
		/* bv term to bbt */
		err = check_bb_term(st, bbt_eq->args[0], bbt_eq->args[1]);
	else if (is_bool(bv->code))
		/* bv atom to bbt */
		err = check_bb_atom(st, bv, bbt);
	else
		return -EINVAL;

	if (err)
		return err;
	return set_step_fact_id(st, step->args[0]);
}
POLY_NORM: { /* Equality of polynomial normal form */
	struct bcf_expr *bv_eq;

	ENSURE(!premise_cnt && param_cnt == 1);
	bv_eq = get_bool_arg(st, step->args[0]);
	CHECK_PTR(bv_eq);
	ENSURE(is_bool_eq(bv_eq->code));
	return apply_trusted_step(st, "POLY_NORM", step->args[0]);
}
POLY_NORM_EQ: { /* Polynomial normalization for relations */
	struct bcf_expr *mul0, *mul1;
	struct bcf_expr *sub0, *sub1;
	struct bcf_expr_ref *eq0, *eq1;

	ENSURE(premise_cnt == 1 && !param_cnt);

	premise = get_premise(st, step, 0);
	ENSURE(is_bool_eq(premise->code));

	/* Premise c0*(x0 - x1) = c1* (y0 == y1)*/
	mul0 = id_to_expr(st, premise->args[0]);
	mul1 = id_to_expr(st, premise->args[1]);
	ENSURE(is_bv_mul(mul0->code) && mul0->vlen == 2);
	ENSURE(is_bv_mul(mul1->code) && mul1->vlen == 2);

	/* Lhs of the multiplication (c0 and c1) must be an odd number. */
	sub0 = id_to_expr(st, mul0->args[0]);
	sub1 = id_to_expr(st, mul1->args[0]);
	ENSURE(is_bv_val(sub0->code) && bv_val(sub0) & 1);
	ENSURE(is_bv_val(sub1->code) && bv_val(sub1) & 1);

	sub0 = id_to_expr(st, mul0->args[1]);
	sub1 = id_to_expr(st, mul1->args[1]);
	ENSURE(is_bv_sub(sub0->code) && is_bv_sub(sub1->code));

	/* Concludes (x0 == x1) = (y0 == y1)*/
	eq0 = build_bool_eq(st, sub0->args[0], sub0->args[1]);
	CHECK_PTR(eq0);
	eq1 = build_bool_eq(st, sub1->args[0], sub1->args[1]);
	CHECK_PTR(eq1);
	fact = build_bool_eq_move(st, eq0->id, eq1->id);
	return set_step_fact(st, fact);
}

bad_rule:
	WARN_ONCE(1, "Unknown bv rule: %u", BCF_STEP_RULE(step->rule));
	return -EFAULT;
}
#undef DEFINE_JUMP_TABLE
#undef RULE_TBL

/* Format a bcf_expr as an s-expression into buf. Returns number of bytes
 * written (excluding the trailing NUL) or a negative errno on error.
 */
static int format_sexpr(struct bcf_checker_state *st, struct bcf_expr *root,
			char *buf, size_t buf_size, u32 depth)
{
	struct bcf_expr_stack_elem stack[BCF_MAX_ITER_STACK];
	u32 sp = 0;
	size_t off = 0;

#define APPENDF(fmt, ...)                                                   \
	do {                                                                \
		size_t __n = scnprintf(buf + off,                           \
				       buf_size > off ? buf_size - off : 0, \
				       fmt, ##__VA_ARGS__);                 \
		if (__n <= 0 || off + __n >= buf_size)                      \
			return -ENOSPC;                                     \
		off += __n;                                                 \
	} while (0)

	stack[sp++] =
		(struct bcf_expr_stack_elem){ .expr = root, .cur_arg = 0 };

	while (sp) {
		struct bcf_expr_stack_elem *top = &stack[sp - 1];
		struct bcf_expr *e = top->expr;
		u8 ty = BCF_TYPE(e->code);
		u8 op = BCF_OP(e->code);

		if (!top->cur_arg) {
			/* Leaf constants. */
			if (is_bool_val(e->code)) {
				APPENDF("%s", BCF_BOOL_LITERAL(e->params) ?
						      "true" :
						      "false");
				sp--;
				continue;
			}
			if (is_bv_val(e->code)) {
				/* (_ bv<val> <width>) */
				APPENDF("(_ bv%llu %u)", bv_val(e), bv_size(e));
				sp--;
				continue;
			}

			/* Open node */
			if (ty == BCF_BV &&
			    (op == BCF_EXTRACT || op == BCF_SIGN_EXTEND ||
			     op == BCF_ZERO_EXTEND || op == BCF_REPEAT)) {
				/* Indexed ops. Close inner index list before args. */
				if (op == BCF_EXTRACT) {
					APPENDF("((_ extract %u %u) ",
						BCF_EXTRACT_START(e->params),
						BCF_EXTRACT_END(e->params));
				} else if (op == BCF_SIGN_EXTEND) {
					APPENDF("((_ sign_extend %u) ",
						BCF_EXT_LEN(e->params));
				} else if (op == BCF_ZERO_EXTEND) {
					APPENDF("((_ zero_extend %u) ",
						BCF_EXT_LEN(e->params));
				} else { /* BCF_REPEAT */
					APPENDF("((_ repeat %u) ",
						BCF_REPEAT_N(e->params));
				}
			} else if (ty == BCF_BOOL && op == BCF_BITOF) {
				/* Boolean bit-of (indexed). */
				APPENDF("((_ bit %u) ",
					BCF_BITOF_BIT(e->params));
			} else {
				APPENDF("(%s(%u)", code_str(e->code), e->vlen);
				/* Embed BV size. */
				if (ty == BCF_BV && op == BCF_VAR)
					APPENDF(" %u", bv_size(e));
				if (e->vlen)
					APPENDF(" ");
			}

			if (!e->vlen) {
				/* Nullary node */
				APPENDF(")");
				sp--;
				continue;
			}
		}

		/* Emit arguments */
		if (top->cur_arg < e->vlen) {
			u32 arg_id = e->args[top->cur_arg++];

			if (!expr_arg_is_id(e->code))
				/* Non-ID args only occur for BV_VAL and were handled above. */
				return -EFAULT;

			if (top->cur_arg > 1)
				APPENDF(" ");

			if (top->cur_arg > 4) {
				APPENDF("...");
				top->cur_arg = e->vlen;
				continue;
			}

			if (sp >= depth) {
				APPENDF("@t%u", arg_id);
				continue;
			}

			if (sp >= BCF_MAX_ITER_STACK)
				return -E2BIG;
			stack[sp++] = (struct bcf_expr_stack_elem){
				.expr = id_to_expr(st, arg_id), .cur_arg = 0
			};
			continue;
		}

		/* Close node */
		APPENDF(")");
		sp--;
	}
#undef APPENDF
	return off;
}

static void verbose_expr(struct bcf_checker_state *st, struct bcf_expr *expr,
			 u32 depth)
{
	char buf[1024];
	int ret;

	ret = format_sexpr(st, expr, buf, 1024, depth);
	if (ret < 0)
		buf[1023] = 0;
	verbose(st, "%s", buf);
}

static void verbose_expr_id(struct bcf_checker_state *st, u32 id, u32 depth)
{
	verbose_expr(st, id_to_expr(st, id), depth);
}

static const char *rule_str(u16 rule)
{
#define RULE_STR_TBL(rule) [BCF_RULE_NAME(rule)] = __stringify(rule),
	static const char *const core_rule_str[__MAX_BCF_CORE_RULES] = {
		[0 ... __MAX_BCF_CORE_RULES - 1] = "unknown core rule",
		BCF_CORE_RULES(RULE_STR_TBL)
	};
	static const char *const bool_rule_str[__MAX_BCF_BOOL_RULES] = {
		[0 ... __MAX_BCF_BOOL_RULES - 1] = "unknown boolean rule",
		BCF_BOOL_RULES(RULE_STR_TBL)
	};
	static const char *const bv_rule_str[__MAX_BCF_BV_RULES] = {
		[0 ... __MAX_BCF_BV_RULES - 1] = "unknown bv rule",
		BCF_BV_RULES(RULE_STR_TBL)
	};
#undef RULE_STR_TBL
	u8 class_rule = BCF_STEP_RULE(rule);

	switch (BCF_RULE_CLASS(rule)) {
	case BCF_RULE_CORE:
		return core_rule_str[class_rule];
	case BCF_RULE_BOOL:
		return bool_rule_str[class_rule];
	case BCF_RULE_BV:
		return bv_rule_str[class_rule];
	default:
		WARN_ONCE(1, "Unknown rule class: %u", BCF_RULE_CLASS(rule));
		return "unknown rule class";
	}
}

static void verbose_step(struct bcf_checker_state *st,
			 struct bcf_proof_step *step, u32 step_id)
{
	const char *rule_name = rule_str(step->rule);
	struct bcf_expr *fact;
	char buf[1024];

	if (!(st->level & BPF_LOG_LEVEL2))
		return;

	verbose(st, "(#%d %s (", step_id, rule_name);

	/* Print premises */
	for (u32 i = 0; i < step->premise_cnt; i++) {
		verbose(st, "@p%d", step->args[i]);

		if (i >= 3) {
			verbose(st, "...");
			break;
		}
		if (i + 1 != step->premise_cnt)
			verbose(st, " ");
	}

	verbose(st, ") (");

	/* Print parameters */
	for (u32 i = 0, j = step->premise_cnt; i < step->param_cnt; i++, j++) {
		if (i >= 3) {
			verbose(st, "@t...");
			break;
		}
		if (i != 0) {
			verbose(st, ", @t%d", step->args[j]);
			continue;
		}
		if (step->rule == (BCF_RULE_CORE | BCF_RULE_REWRITE)) {
			u32 rid = step->args[j];
			const char *name = rid ? bcf_rewrites[rid]->name :
						 "trusted";
			verbose(st, "%s", name);
		} else if (step->rule == (BCF_RULE_BV | BCF_RULE_BITBLAST)) {
			verbose_expr_id(st, step->args[j], 2);
		} else if (valid_arg_id(st, step->args[j])) {
			verbose_expr_id(st, step->args[j], 1);
		} else {
			verbose(st, "@t%d", step->args[j]);
		}
	}
	verbose(st, ")");

	fact = st->step_state[step_id].fact;
	if (fact) {
		int ret;

		ret = format_sexpr(st, fact, buf, 1024, 2);
		if (ret < 0)
			buf[1023] = 0;
		verbose(st, "\n\t\t(%s :conclusion)", buf);
	}
	verbose(st, ")\n");
}

static int apply_rules(struct bcf_checker_state *st)
{
	struct bcf_expr *fact;
	int err;

	verbose(st, "checking %u steps\n", st->step_cnt);

	while (st->cur_step_idx < st->step_size) {
		struct bcf_proof_step *step = st->steps + st->cur_step_idx;
		u16 class = BCF_RULE_CLASS(step->rule);

		if (signal_pending(current))
			return -EAGAIN;
		if (need_resched())
			cond_resched();

		if (class == BCF_RULE_CORE)
			err = apply_core_rule(st, step);
		else if (class == BCF_RULE_BOOL)
			err = apply_bool_rule(st, step);
		else if (class == BCF_RULE_BV)
			err = apply_bv_rule(st, step);
		else {
			WARN_ONCE(1, "Unknown rule class: %u", class);
			err = -EFAULT;
		}

		verbose_step(st, step, st->cur_step);
		if (err)
			return err;

		st->cur_step_idx += STEP_SZ(step);
		st->cur_step++;
	}

	/* The last step must refute the goal by concluding `false` */
	fact = st->step_state[st->step_cnt - 1].fact;
	ENSURE(is_false(fact));
	verbose(st, "proof accepted\n");

	return 0;
}

static int check_hdr(struct bcf_proof_header *hdr, bpfptr_t proof,
		     u32 proof_size)
{
	u32 expr_size, step_size, sz;
	bool overflow = false;

	ENSURE(proof_size < MAX_BCF_PROOF_SIZE && proof_size > sizeof(*hdr) &&
	       (proof_size % sizeof(u32) == 0));

	if (copy_from_bpfptr(hdr, proof, sizeof(*hdr)))
		return -EFAULT;

	ENSURE(hdr->magic == BCF_MAGIC && hdr->expr_cnt && hdr->step_cnt > 1);

	overflow |= check_mul_overflow(hdr->expr_cnt, sizeof(struct bcf_expr),
				       &expr_size);
	overflow |= check_mul_overflow(
		hdr->step_cnt, sizeof(struct bcf_proof_step), &step_size);
	overflow |= check_add_overflow(expr_size, step_size, &sz);
	ENSURE(!overflow && (proof_size - sizeof(*hdr)) == sz);

	return 0;
}

int bcf_check_proof(struct bcf_expr *goal_exprs, u32 goal, bpfptr_t proof,
		    u32 proof_size, bcf_logger_t logger, u32 level,
		    void *private)
{
	struct bcf_checker_state *st __free(free_checker) = NULL;
	struct bcf_proof_header hdr;
	int err;

	err = check_hdr(&hdr, proof, proof_size);
	if (err)
		return err;

	st = kzalloc(sizeof(*st), GFP_KERNEL_ACCOUNT);
	if (!st)
		return -ENOMEM;
	xa_init(&st->expr_id_map);
	st->goal_exprs = goal_exprs;
	st->goal = goal;
	st->logger = logger;
	st->logger_private = private;
	st->level = level;

	bpfptr_add(&proof, sizeof(struct bcf_proof_header));
	err = check_exprs(st, proof, hdr.expr_cnt);

	bpfptr_add(&proof, hdr.expr_cnt * sizeof(struct bcf_expr));
	err = err ?: check_steps(st, proof, hdr.step_cnt);
	err = err ?: apply_rules(st);
	return err;
}
EXPORT_SYMBOL_GPL(bcf_check_proof);
