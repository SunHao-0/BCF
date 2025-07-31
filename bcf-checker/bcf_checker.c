#include <linux/overflow.h>
#include <linux/limits.h>
#include <linux/errno.h>
#include <linux/xarray.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/refcount.h>
#include <linux/bitmap.h>
#include <linux/sched/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/cleanup.h>
#include <linux/bpfptr.h>
#include <linux/bpf_verifier.h>
#include <linux/bcf.h>
#include <linux/bpf.h>

#define BCF_MAX_CMP_STACK 128
struct bcf_cmp_state {
	struct bcf_expr *e0, *e1;
	u32 cur_arg;
};

struct bcf_step_state {
	struct bcf_expr *fact;
	u32 fact_id;
	/* Indices of the last step referring to the step (id).
	 * After this step, the fact of the referred step is no
	 * longer used.
	 */
	u32 last_ref;
};

// clang-format off
struct bcf_checker_state {
	struct bpf_verifier_env *verifier_env;

	/* Static expressions from bcf_buf */
	struct bcf_expr	*exprs;
	unsigned long	*valid_idx;	/* bitmap for valid indices */
	u32		expr_size;	/* size of exprs array */

	/* Dynamic expression (produced by steps) management */
	u32		id_gen;		/* expr id starting from `expr_size` */
	struct xarray	expr_id_map;	/* id to ptr for dynamic exprs */

	/* Builtin expressions */
	u32 true_expr;
	u32 false_expr;

	/* Step state tracking */
	struct bcf_proof_step	*steps;
	u32 step_size;		/* size of steps array */
	u32 step_cnt;		/* valid number of steps */
	u32 cur_step;
	u32 cur_step_idx;
	struct bcf_step_state *step_state;

	struct bcf_expr_buf expr_buf;
	struct bcf_expr_unary not_expr;	/* Used by resolution */

	/* Stack for expr equiv comparison */
	struct bcf_cmp_state expr_stack[BCF_MAX_CMP_STACK];
};
// clang-format on

static void free_checker_state(struct bcf_checker_state *st)
{
	struct bcf_expr_ref *eref;
	unsigned long id;

	kvfree(st->exprs);
	kvfree(st->valid_idx);
	xa_for_each(&st->expr_id_map, id, eref) {
		kfree(eref);
	}
	xa_destroy(&st->expr_id_map);
	kvfree(st->steps);
	kvfree(st->step_state);

	kfree(st);
}

DEFINE_FREE(free_checker, struct bcf_checker_state *,
	    if (_T) free_checker_state(_T))

#define bcf_for_each_arg(arg_id, expr)                                   \
	for (u32 ___i = 0, arg_id;                                       \
	     ___i < (expr)->vlen && (arg_id = (expr)->args[___i], true); \
	     ___i++)

#define bcf_for_each_expr(arg_expr, expr, st)                                  \
	for (u32 ___i = 0, ___id;                                              \
	     ___i < (expr)->vlen && (___id = (expr)->args[___i],               \
				    arg_expr = id_to_expr((st), ___id), true); \
	     ___i++)

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

#define EXPR_SZ(expr) ((expr)->vlen + 1)
#define STEP_SZ(step) ((step)->premise_cnt + (step)->param_cnt + 1)

#define ENSURE(cond)                    \
	do {                            \
		if (!(cond))            \
			return -EINVAL; \
	} while (0)

#define CHECK_PTR(ptr)                         \
	do {                                   \
		if (IS_ERR((ptr)))             \
			return PTR_ERR((ptr)); \
	} while (0)

#define CHECK_PTR2(ptr)                    \
	do {                               \
		if (IS_ERR_OR_NULL((ptr))) \
			return (ptr);      \
	} while (0)

static bool is_valid_arg(struct bcf_checker_state *st, u32 idx)
{
	return idx < st->expr_size && test_bit(idx, st->valid_idx);
}

static bool is_bool(u8 code)
{
	return BCF_TYPE(code) == BCF_BOOL;
}

static bool is_bv(u8 code)
{
	return BCF_TYPE(code) == BCF_BV;
}

static bool is_not(u8 code)
{
	return code == (BCF_BOOL | BCF_NOT);
}

static bool is_equiv(u8 code)
{
	return code == (BCF_BOOL | BPF_JEQ);
}

static bool is_implies(u8 code)
{
	return code == (BCF_BOOL | BCF_IMPLIES);
}

static bool is_conj(u8 code)
{
	return code == (BCF_BOOL | BCF_CONJ);
}

static bool is_disj(u8 code)
{
	return code == (BCF_BOOL | BCF_DISJ);
}

static bool is_xor(u8 code)
{
	return code == (BCF_BOOL | BCF_XOR);
}

static bool is_ite(u8 code)
{
	return code == (BCF_BOOL | BCF_ITE);
}

static bool is_true(struct bcf_expr *expr)
{
	return expr->code == (BCF_BOOL | BCF_VAL) && expr->params == BCF_TRUE;
}

static bool is_false(struct bcf_expr *expr)
{
	return expr->code == (BCF_BOOL | BCF_VAL) && expr->params == BCF_FALSE;
}

static bool is_bv_val(u8 code)
{
	return code == (BCF_BV | BCF_VAL);
}

static bool is_from_bool(u8 code)
{
	return code == (BCF_BV | BCF_FROM_BOOL);
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
/* Ref-counted bcf_expr */
struct bcf_expr_ref {
	union {
		struct {
			refcount_t refcnt;
			u32 id;
		};
		/* For free list, see expr_put() */
		struct bcf_expr_ref *free_next;
	};
	struct bcf_expr expr;
};

static struct bcf_expr_ref *alloc_expr(struct bcf_checker_state *st, u8 arg_n)
{
	struct bcf_expr_ref *eref;
	void *entry;

	eref = kmalloc(struct_size(eref, expr.args, arg_n), GFP_KERNEL);
	if (!eref)
		return ERR_PTR(-ENOMEM);

	eref->id = st->id_gen++;
	eref->expr.vlen = arg_n;
	entry = xa_store(&st->expr_id_map, eref->id, eref, GFP_KERNEL);
	if (xa_is_err(entry)) {
		kfree(eref);
		return ERR_PTR(-ENOMEM);
	}

	/* The caller owns the expr */
	refcount_set(&eref->refcnt, 1);
	return eref;
}

static struct bcf_expr_ref *__to_eref(struct bcf_expr *expr)
{
	return container_of(expr, struct bcf_expr_ref, expr);
}

static bool is_static_expr(struct bcf_checker_state *st, struct bcf_expr *expr)
{
	return expr >= st->exprs && expr < st->exprs + st->expr_size;
}

static bool is_static_expr_id(struct bcf_checker_state *st, u32 id)
{
	return id < st->expr_size;
}

static struct bcf_expr_ref *to_eref(struct bcf_checker_state *st,
				    struct bcf_expr *expr)
{
	return is_static_expr(st, expr) ? ERR_PTR(-EINVAL) : __to_eref(expr);
}

static struct bcf_expr_ref *id_to_eref(struct bcf_checker_state *st, u32 id)
{
	return is_static_expr_id(st, id) ? ERR_PTR(-EINVAL) :
					   xa_load(&st->expr_id_map, id);
}

static struct bcf_expr *id_to_expr(struct bcf_checker_state *st, u32 id)
{
	struct bcf_expr_ref *eref;

	if (is_static_expr_id(st, id))
		return st->exprs + id;

	eref = xa_load(&st->expr_id_map, id);
	return eref ? &eref->expr : ERR_PTR(-EINVAL);
}

/* Obtain the expr referred to by a step, which is part of the proof and
 * only locate in the static exprs.
 */
static struct bcf_expr *get_arg_expr(struct bcf_checker_state *st, u32 id)
{
	return is_static_expr_id(st, id) ? st->exprs + id : ERR_PTR(-EINVAL);
}

static struct bcf_expr *get_list_arg(struct bcf_checker_state *st, u32 id)
{
	struct bcf_expr *e = get_arg_expr(st, id);
	if (!e || !is_list(e->code))
		return ERR_PTR(-EINVAL);
	return e;
}

static struct bcf_expr *get_bool_arg(struct bcf_checker_state *st, u32 id)
{
	struct bcf_expr *e = get_arg_expr(st, id);
	if (!e || !is_bool(e->code))
		return ERR_PTR(-EINVAL);
	return e;
}

static struct bcf_expr *get_expr_buf(struct bcf_checker_state *st)
{
	st->expr_buf.code = 0;
	st->expr_buf.vlen = 0;
	st->expr_buf.params = 0;
	return (void *)&st->expr_buf;
}

static void expr_get(struct bcf_checker_state *st, struct bcf_expr *expr)
{
	struct bcf_expr_ref *eref = to_eref(st, expr);
	if (eref)
		refcount_inc(&eref->refcnt);
}

static void expr_id_get(struct bcf_checker_state *st, u32 id)
{
	struct bcf_expr_ref *eref = id_to_eref(st, id);
	if (eref)
		refcount_inc(&eref->refcnt);
}

static void push_free(struct bcf_checker_state *st, struct bcf_expr_ref **head,
		      struct bcf_expr_ref *eref)
{
	if (eref && refcount_dec_and_test(&eref->refcnt)) {
		xa_erase(&st->expr_id_map, eref->id);
		eref->free_next = *head;
		*head = eref;
	}
}

static struct bcf_expr_ref *pop_free(struct bcf_expr_ref **head)
{
	struct bcf_expr_ref *eref = *head;
	if (eref)
		*head = eref->free_next;
	return eref;
}

static void expr_put(struct bcf_checker_state *st, struct bcf_expr *expr)
{
	struct bcf_expr_ref *free_head = NULL;

	push_free(st, &free_head, to_eref(st, expr));

	while (free_head) {
		struct bcf_expr_ref *eref = pop_free(&free_head);

		bcf_for_each_arg(arg_id, &eref->expr)
			push_free(st, &free_head, id_to_eref(st, arg_id));

		kfree(eref);
	}
}

static void eref_put(struct bcf_checker_state *st, struct bcf_expr_ref *eref)
{
	expr_put(st, &eref->expr);
}

/* ty/op/arity table */
// clang-format off
#define Nullary		{ 0, 0 }
#define Unary		{ 1, 1 }
#define Binary		{ 2, 2 }
#define Ternary		{ 3, 3 }
#define Vari(l)		{ (l), U8_MAX }
// clang-format on
#define BCF_OP_TABLE(MAPPER)                   \
	MAPPER(BCF_BV, BPF_ADD, Vari(2))       \
	MAPPER(BCF_BV, BPF_SUB, Binary)        \
	MAPPER(BCF_BV, BPF_MUL, Vari(2))       \
	MAPPER(BCF_BV, BPF_DIV, Binary)        \
	MAPPER(BCF_BV, BPF_OR, Vari(2))        \
	MAPPER(BCF_BV, BPF_AND, Vari(2))       \
	MAPPER(BCF_BV, BPF_LSH, Binary)        \
	MAPPER(BCF_BV, BPF_RSH, Binary)        \
	MAPPER(BCF_BV, BPF_NEG, Unary)         \
	MAPPER(BCF_BV, BPF_MOD, Binary)        \
	MAPPER(BCF_BV, BPF_XOR, Vari(2))       \
	MAPPER(BCF_BV, BPF_ARSH, Binary)       \
	MAPPER(BCF_BV, BCF_VAL, Vari(1))       \
	MAPPER(BCF_BV, BCF_VAR, Nullary)       \
	MAPPER(BCF_BV, BCF_ITE, Ternary)       \
	MAPPER(BCF_BV, BCF_SDIV, Binary)       \
	MAPPER(BCF_BV, BCF_SMOD, Binary)       \
	MAPPER(BCF_BV, BCF_EXTRACT, Unary)     \
	MAPPER(BCF_BV, BCF_SIGN_EXTEND, Unary) \
	MAPPER(BCF_BV, BCF_ZERO_EXTEND, Unary) \
	MAPPER(BCF_BV, BCF_CONCAT, Vari(2))    \
	MAPPER(BCF_BV, BCF_BVSIZE, Unary)      \
	MAPPER(BCF_BV, BCF_FROM_BOOL, Vari(1)) \
	MAPPER(BCF_BOOL, BPF_JEQ, Binary)      \
	MAPPER(BCF_BOOL, BPF_JGT, Binary)      \
	MAPPER(BCF_BOOL, BPF_JGE, Binary)      \
	MAPPER(BCF_BOOL, BPF_JSGT, Binary)     \
	MAPPER(BCF_BOOL, BPF_JSGE, Binary)     \
	MAPPER(BCF_BOOL, BPF_JLT, Binary)      \
	MAPPER(BCF_BOOL, BPF_JLE, Binary)      \
	MAPPER(BCF_BOOL, BPF_JSLT, Binary)     \
	MAPPER(BCF_BOOL, BPF_JSLE, Binary)     \
	MAPPER(BCF_BOOL, BCF_VAL, Nullary)     \
	MAPPER(BCF_BOOL, BCF_VAR, Nullary)     \
	MAPPER(BCF_BOOL, BCF_ITE, Ternary)     \
	MAPPER(BCF_BOOL, BCF_CONJ, Vari(2))    \
	MAPPER(BCF_BOOL, BCF_DISJ, Vari(2))    \
	MAPPER(BCF_BOOL, BCF_DISTINCT, Binary) \
	MAPPER(BCF_BOOL, BCF_NOT, Unary)       \
	MAPPER(BCF_BOOL, BCF_IMPLIES, Binary)  \
	MAPPER(BCF_BOOL, BCF_XOR, Vari(2))     \
	MAPPER(BCF_BOOL, BCF_BITOF, Unary)     \
	MAPPER(BCF_LIST, BCF_VAL, Vari(1))

static bool in_codetable(u8 code)
{
	// clang-format off
#define CODE_TBL(ty, op, arity) [ty | op] = true,
	static const bool codetable[256] = {
		[0 ... 255] = false,
		BCF_OP_TABLE(CODE_TBL)
	};
#undef CODE_TBL
	// clang-format on
	return codetable[code];
}

static bool valid_vlen(u8 code, u8 vlen)
{
	// clang-format off
#define ARITY_TBL(ty, op, arity) [ty | op] = arity,
	static const struct bcf_arity {
		u8 min, max;
	} arity[256] = {
		[0 ... 255] = Nullary,
		BCF_OP_TABLE(ARITY_TBL)
	};
#undef ARITY_TBL
	// clang-format on
	return vlen >= arity[code].min && vlen <= arity[code].max;
}

static bool valid_bv_sz(u32 sz)
{
	return sz == 8 || sz == 16 || sz == 32 || sz == 64;
}

static u8 bv_size(struct bcf_expr *expr)
{
	u8 op = BCF_OP(expr->code);
	u16 params = expr->params;

	if (op != BCF_EXTRACT)
		return BCF_BV_WIDTH(params);
	return BCF_EXTRACT_START(params) - BCF_EXTRACT_END(params) + 1;
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

static int check_bv_expr(struct bcf_checker_state *st, struct bcf_expr *expr)
{
	u32 bit_sz = BCF_BV_WIDTH(expr->params);
	u8 op = BCF_OP(expr->code);
	struct bcf_expr *arg = NULL;

	if (expr->vlen && op != BCF_VAL)
		arg = st->exprs + expr->args[0];

	if (op == BCF_EXTRACT) {
		u32 start = BCF_EXTRACT_START(expr->params);
		u32 end = BCF_EXTRACT_END(expr->params);

		if (start < end)
			return -EINVAL;

		if (!is_bv(arg->code) || bv_size(arg) <= start)
			return -EINVAL;
		return 0;
	}

	if (op == BCF_ZERO_EXTEND || op == BCF_SIGN_EXTEND) {
		u32 ext_sz = BCF_EXT_LEN(expr->params);

		if (!bit_sz || !ext_sz || bit_sz <= ext_sz)
			return -EINVAL;

		if (!is_bv(arg->code) || bv_size(arg) + ext_sz != bit_sz)
			return -EINVAL;
		return 0;
	}

	if (BCF_PARAM_HIGH(expr->params) || !bit_sz)
		return -EINVAL;

	switch (op) {
	case BCF_VAL: {
		u32 arg_len = bit_sz / 32;
		u32 mask;

		if (!valid_bv_sz(bit_sz))
			return -EINVAL;

		if (!arg_len) {
			mask = (1U << bit_sz) - 1;
			arg_len = 1;
			if (expr->args[0] & ~mask)
				return -EINVAL;
		}
		return (arg_len == expr->vlen) ? 0 : -EINVAL;
	}
	case BCF_CONCAT: {
		u64 sz = 0;

		bcf_for_each_expr(arg, expr, st) {
			if (!is_bv(arg->code))
				return -EINVAL;
			sz += bv_size(arg);
		}
		return (sz == bit_sz) ? 0 : -EINVAL;
	}
	case BCF_FROM_BOOL:
		bcf_for_each_expr(arg, expr, st) {
			if (!is_bool(arg->code))
				return -EINVAL;
		}
		return (expr->vlen == bit_sz) ? 0 : -EINVAL;
	case BCF_BVSIZE:
		if (!valid_bv_sz(bit_sz))
			return -EINVAL;
		return is_bv(arg->code) ? 0 : -EINVAL;
	default:
		/* For all other operators, ensure type matches */
		bcf_for_each_arg_expr(i, arg, expr, st) {
			if (op == BCF_ITE && i == 0) {
				if (!is_bool(arg->code))
					return -EINVAL;
			} else if (!same_type(expr, arg)) {
				return -EINVAL;
			}
		}
		break;
	}

	return 0;
}

static int check_bool_expr(struct bcf_checker_state *st, struct bcf_expr *expr)
{
	struct bcf_expr *arg0 = NULL, *arg1 = NULL;
	u8 op = BCF_OP(expr->code);

	if (op != BCF_BITOF && op != BCF_VAL && expr->params)
		return -EINVAL;

	if (expr->vlen)
		arg0 = st->exprs + expr->args[0];
	if (expr->vlen > 1)
		arg1 = st->exprs + expr->args[1];

	switch (op) {
	case BPF_JEQ:
	case BPF_JGT:
	case BPF_JGE:
	case BPF_JSGT:
	case BPF_JSGE:
	case BPF_JLT:
	case BPF_JLE:
	case BPF_JSLT:
	case BPF_JSLE:
		if (!is_bv(arg0->code) || !is_bv(arg1->code) ||
		    !same_type(arg0, arg1))
			return -EINVAL;
		break;
	case BCF_DISTINCT:
		if (!same_type(arg0, arg1))
			return -EINVAL;
		break;
	case BCF_BITOF: {
		u32 bit = BCF_PARAM_HIGH(expr->params);
		u32 bit_sz = BCF_PARAM_LOW(expr->params);

		if (!is_bv(arg0->code) || bv_size(arg0) != bit_sz ||
		    bit >= bit_sz)
			return -EINVAL;
		break;
	}
	case BCF_VAL:
		if (expr->params != BCF_TRUE && expr->params != BCF_FALSE)
			return -EINVAL;
		break;
	default:
		/* For all other operators, ensure all args are bool */
		bcf_for_each_expr(arg0, expr, st) {
			if (!is_bool(arg0->code))
				return -EINVAL;
		}
		break;
	}

	return 0;
}

static int check_list_expr(struct bcf_checker_state *st, struct bcf_expr *expr)
{
	struct bcf_expr elem_ty = { 0 };
	struct bcf_expr *arg;
	u16 ty = BCF_PARAM_HIGH(expr->params);
	u16 params = BCF_PARAM_LOW(expr->params);

	if (ty != BCF_BOOL && ty != BCF_BV)
		return -EINVAL;

	elem_ty.code = ty;
	elem_ty.params = params;

	bcf_for_each_expr(arg, expr, st) {
		if (!same_type(&elem_ty, arg))
			return -EINVAL;
	}

	return 0;
}

static int check_expr_type(struct bcf_checker_state *st, struct bcf_expr *expr)
{
	u8 ty = BCF_TYPE(expr->code);

	if (!in_codetable(expr->code))
		return -EINVAL;

	if (!valid_vlen(expr->code, expr->vlen))
		return -EINVAL;

	if (ty == BCF_BV)
		return check_bv_expr(st, expr);
	else if (ty == BCF_BOOL)
		return check_bool_expr(st, expr);
	else if (ty == BCF_LIST)
		return check_list_expr(st, expr);

	return -EFAULT;
}

static int check_exprs(struct bcf_checker_state *st, bpfptr_t bcf_buf,
		       u32 expr_size)
{
	struct {
		u32 *target;
		u32 params;
		bool need_alloc;
	} builtins[] = {
		{ &st->true_expr, BCF_TRUE, true },
		{ &st->false_expr, BCF_FALSE, true },
	};
	u32 idx = 0;
	int err;

	st->exprs = kvmemdup_bpfptr(bcf_buf, expr_size * sizeof(u32));
	if (IS_ERR(st->exprs)) {
		err = PTR_ERR(st->exprs);
		st->exprs = NULL;
		return err;
	}

	st->valid_idx = kvzalloc(bitmap_size(expr_size), GFP_KERNEL);
	if (!st->valid_idx) {
		kvfree(st->exprs);
		st->exprs = NULL;
		return -ENOMEM;
	}

	st->expr_size = expr_size;
	st->id_gen = expr_size;

	while (idx < expr_size) {
		struct bcf_expr *expr = st->exprs + idx;
		u32 expr_sz = EXPR_SZ(expr);

		if (idx + expr_sz > expr_size)
			return -EINVAL;

		bcf_for_each_arg(arg, expr) {
			/* BV literals contain values, not arg indices */
			if (expr->code == (BCF_BV | BCF_VAL))
				break;
			/* An expr can only refer to preceding exprs */
			if (!is_valid_arg(st, arg))
				return -EINVAL;
		}

		err = check_expr_type(st, expr);
		if (err)
			return err;

		if (builtins[0].need_alloc && is_true(expr)) {
			*builtins[0].target = idx;
			builtins[0].need_alloc = false;
		}
		if (builtins[1].need_alloc && is_false(expr)) {
			*builtins[1].target = idx;
			builtins[1].need_alloc = false;
		}

		set_bit(idx, st->valid_idx);
		idx += expr_sz;
	}

	if (idx != expr_size)
		return -EINVAL;

	for (int i = 0; i < ARRAY_SIZE(builtins); i++) {
		if (builtins[i].need_alloc) {
			struct bcf_expr_ref *expr_ref = alloc_expr(st, 0);
			CHECK_PTR(expr_ref);
			expr_ref->expr.code = BCF_BOOL | BCF_VAL;
			expr_ref->expr.params = builtins[i].params;
			*builtins[i].target = expr_ref->id;
		}
	}

	return 0;
}

static u64 bv_val(struct bcf_expr *bv)
{
	u64 val = bv->args[0];

	if (bv->vlen > 1) {
		BUG_ON(bv->vlen != 2);
		val |= ((u64)bv->args[1] << 32);
	}
	return val;
}

static bool expr_node_equiv(struct bcf_expr *e0, struct bcf_expr *e1)
{
	if (e0->code != e1->code || e0->vlen != e1->vlen ||
	    e0->params != e1->params)
		return false;
	return is_bv_val(e0->code) ? bv_val(e0) == bv_val(e1) : true;
}

#define BCF_MAX_VAR_MAP 128
struct bcf_var_map {
	struct {
		u32 idx0;
		u32 idx1;
	} pair[BCF_MAX_VAR_MAP];
	u32 cnt;
};

static int var_equiv(struct bcf_var_map *map, u32 v0, u32 v1)
{
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

static struct bcf_expr *verifier_id_to_expr(struct bcf_checker_state *st,
					    u32 id)
{
	struct bcf_state *bcf = &st->verifier_env->bcf;

	return bcf->exprs + id;
}

static int __expr_equiv(struct bcf_checker_state *st, struct bcf_expr *e0,
			struct bcf_expr *e1, bool from_checker)
{
	struct bcf_cmp_state *stack = st->expr_stack;
	struct bcf_var_map map = { 0 };
	u32 stack_size = 0;
	int ret;

	if (!expr_node_equiv(e0, e1))
		return 0;
	if (!e0->vlen || is_bv_val(e0->code) || e0 == e1)
		return 1;

	stack[stack_size++] = (struct bcf_cmp_state){ e0, e1, 0 };

	while (stack_size) {
		struct bcf_cmp_state *cmp = &stack[--stack_size];

		while (cmp->cur_arg < cmp->e0->vlen) {
			u32 arg0 = cmp->e0->args[cmp->cur_arg];
			u32 arg1 = cmp->e1->args[cmp->cur_arg];
			struct bcf_expr *a0, *a1;

			cmp->cur_arg++;

			if (from_checker && arg0 == arg1)
				continue;

			/* Resolve argument expressions */
			a0 = id_to_expr(st, arg0);
			a1 = from_checker ? id_to_expr(st, arg1) :
					    verifier_id_to_expr(st, arg1);

			if (!expr_node_equiv(a0, a1))
				return 0;

			if (is_val(a0->code) && !is_list(a0->code))
				continue;

			if (is_var(a0->code)) {
				/* For exprs from bcf_checker_state, same var
				 * must have the same id.
				 */
				if (from_checker)
					return 0;
				ret = var_equiv(&map, arg0, arg1);
				if (ret != 1)
					return ret;
				continue;
			}

			/* Only bool/bv var and bool val has args, must have
			 * been handled above
			 */
			BUG_ON(!a0->vlen);

			if (stack_size + 2 > BCF_MAX_CMP_STACK)
				return -E2BIG;

			/* Push current state back and new comparison */
			stack[stack_size++] = *cmp;
			stack[stack_size++] =
				(struct bcf_cmp_state){ a0, a1, 0 };
			break;
		}
	}

	return 1;
}

static int expr_equiv(struct bcf_checker_state *st, struct bcf_expr *e0,
		      struct bcf_expr *e1)
{
	return __expr_equiv(st, e0, e1, true);
}

static int expr_id_equiv(struct bcf_checker_state *st, u32 i0, u32 i1)
{
	struct bcf_expr *e0, *e1;

	e0 = id_to_expr(st, i0);
	e1 = id_to_expr(st, i1);
	if (!e0 || !e1)
		return -EFAULT;
	return __expr_equiv(st, e0, e1, true);
}

static bool is_refine_cond(struct bcf_checker_state *st, struct bcf_expr *goal)
{
	struct bcf_state *bcf = &st->verifier_env->bcf;
	int ret;

	ret = __expr_equiv(st, goal, bcf->exprs + bcf->goal, false);
	return ret == 1;
}

static bool is_assume(u16 rule)
{
	return BCF_RULE_CLASS(rule) == BCF_RULE_CORE &&
	       BCF_STEP_RULE(rule) == BCF_RULE_ASSUME;
}

static int check_goal(struct bcf_checker_state *st, struct bcf_proof_step *step)
{
	struct bcf_expr *goal;

	if (!is_assume(step->rule) || step->premise_cnt || step->param_cnt != 1)
		return -EINVAL;

	goal = get_arg_expr(st, step->args[0]);
	if (!goal)
		return -EINVAL;

	return is_refine_cond(st, goal) ? 0 : -EINVAL;
}

static u16 rule_class_max(u8 rule)
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
	struct bcf_proof_step *step;
	u32 pos = 0, cur_step = 0;
	int err;

	st->steps = kvmemdup_bpfptr(bcf_buf, step_size * sizeof(u32));
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

		if (BCF_STEP_RULE(step->rule) >= rule_class_max(step->rule))
			return -EINVAL;

		if (pos + STEP_SZ(step) > step_size)
			return -EINVAL;

		/* Every step must only refer to previous established steps */
		bcf_for_each_pm_step(step_id, step) {
			if (step_id >= cur_step)
				return -EINVAL;
		}

		/* Validate rule-specific arity constraints */
		if (BCF_RULE_CLASS(step->rule) == BCF_RULE_CORE) {
			u32 pm_cnt = step->premise_cnt;
			u32 param_cnt = step->param_cnt;

			switch (BCF_STEP_RULE(step->rule)) {
			case BCF_RULE_CONG:
				if (!pm_cnt || param_cnt != 1)
					return -EINVAL;
				break;
			case BCF_RULE_TRANS:
				if (!pm_cnt || param_cnt)
					return -EINVAL;
				break;
			case BCF_RULE_INSTANTIATION:
				if (pm_cnt || !param_cnt)
					return -EINVAL;
				break;
			default:
				if (pm_cnt != 1 || param_cnt)
					return -EINVAL;
				break;
			}
		}

		/* The fist step must introduce a goal that is consistent
		 * to the one required by the verifier.
		 */
		if (cur_step == 0) {
			err = check_goal(st, step);
			if (err)
				return err;
			/* Skip this step */
			st->cur_step_idx += STEP_SZ(step);
			st->cur_step++;
		}

		pos += STEP_SZ(step);
		cur_step++;
	}

	if (pos != step_size)
		return -EINVAL; /* trailing garbage */

	/* Per-step book-keeping array */
	st->step_cnt = cur_step;
	// clang-format off
	st->step_state = kvcalloc(cur_step, sizeof(*st->step_state), GFP_KERNEL);
	// clang-format on
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
		if (!st->step_state[cur_step].last_ref)
			return -EINVAL;

	return 0;
}

static struct bcf_expr_ref *build_expr(struct bcf_checker_state *st, bool move,
				       u8 code, u16 params, u32 vlen, ...)
{
	struct bcf_expr_ref *eref;
	struct bcf_expr *expr;
	va_list args;
	u32 i;

	eref = alloc_expr(st, vlen);
	CHECK_PTR2(eref);
	expr = &eref->expr;
	expr->code = code;
	expr->params = params;
	expr->vlen = vlen;

	va_start(args, vlen);
	for (i = 0; i < vlen; i++) {
		int arg = va_arg(args, int);

		if (arg < 0)
			return ERR_PTR(-EINVAL);
		if (!move)
			expr_id_get(st, arg);
		expr->args[i] = arg;
	}
	va_end(args);

	return eref;
}

static struct bcf_expr_ref *clone_expr(struct bcf_checker_state *st,
				       struct bcf_expr *expr)
{
	struct bcf_expr_ref *eref;

	eref = alloc_expr(st, expr->vlen);
	CHECK_PTR2(eref);
	eref->expr = *expr;

	for (u32 i = 0; i < expr->vlen; i++) {
		expr_id_get(st, expr->args[i]);
		eref->expr.args[i] = expr->args[i];
	}

	return eref;
}

static struct bcf_expr_ref *build_equiv(struct bcf_checker_state *st, u32 e0,
					u32 e1)
{
	return build_expr(st, false, BCF_BOOL | BPF_JEQ, 0, 2, e0, e1);
}

static struct bcf_expr_ref *add_equiv(struct bcf_checker_state *st, u32 e0,
				      u32 e1)
{
	return build_expr(st, true, BCF_BOOL | BPF_JEQ, 0, 2, e0, e1);
}

static struct bcf_expr_ref *build_not(struct bcf_checker_state *st, u32 e0)
{
	return build_expr(st, false, BCF_BOOL | BCF_NOT, 0, 1, e0);
}

static struct bcf_expr_ref *add_not(struct bcf_checker_state *st, u32 e0)
{
	return build_expr(st, true, BCF_BOOL | BCF_NOT, 0, 1, e0);
}

static struct bcf_expr_ref *add_disj(struct bcf_checker_state *st, u32 e0,
				     u32 e1)
{
	return build_expr(st, true, BCF_BOOL | BCF_DISJ, 0, 2, e0, e1);
}

static struct bcf_expr_ref *add_disj3(struct bcf_checker_state *st, u32 e0,
				      u32 e1, u32 e2)
{
	return build_expr(st, true, BCF_BOOL | BCF_DISJ, 0, 3, e0, e1, e2);
}

static struct bcf_expr_ref *add_conj(struct bcf_checker_state *st, u32 e0,
				     u32 e1)
{
	return build_expr(st, true, BCF_BOOL | BCF_CONJ, 0, 2, e0, e1);
}

static struct bcf_expr_ref *add_ite(struct bcf_checker_state *st, u32 e0,
				    u32 e1, u32 e2)
{
	return build_expr(st, true, BCF_BOOL | BCF_ITE, 0, 3, e0, e1, e2);
}

/* Set the conclusion/fact for the current proof step.
 *
 * If expr_ref 'fact' is provided, takes ownership of the expr_ref and
 * stores its ID and expression pointer in the current step state.
 * If 'fact' is NULL, uses the provided 'fact_id', increments its ref
 * count, resolves it to an expression pointer, and stores both.
 *
 * For each premise step, if this current step is marked as the last
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

		if (pm_st->last_ref == st->cur_step) {
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

static struct bcf_expr *get_pm(struct bcf_checker_state *st,
			       struct bcf_proof_step *step, u32 arg)
{
	return st->step_state[step->args[arg]].fact;
}

static u32 get_pm_id(struct bcf_checker_state *st, struct bcf_proof_step *step,
		     u32 arg)
{
	return st->step_state[step->args[arg]].fact_id;
}

#define BCF_CORE_RULES(MAPPER) \
	MAPPER(ASSUME)         \
	MAPPER(INSTANTIATION)  \
	MAPPER(REFL)           \
	MAPPER(SYMM)           \
	MAPPER(TRANS)          \
	MAPPER(CONG)           \
	MAPPER(TRUE_INTRO)     \
	MAPPER(TRUE_ELIM)      \
	MAPPER(FALSE_INTRO)    \
	MAPPER(FALSE_ELIM)

#define BCF_BOOL_RULES(MAPPER)   \
	MAPPER(RESOLUTION)       \
	MAPPER(FACTORING)        \
	MAPPER(REORDERING)       \
	MAPPER(SPLIT)            \
	MAPPER(EQ_RESOLVE)       \
	MAPPER(MODUS_PONENS)     \
	MAPPER(NOT_NOT_ELIM)     \
	MAPPER(CONTRA)           \
	MAPPER(AND_ELIM)         \
	MAPPER(AND_INTRO)        \
	MAPPER(NOT_OR_ELIM)      \
	MAPPER(IMPLIES_ELIM)     \
	MAPPER(NOT_IMPLIES_ELIM) \
	MAPPER(EQUIV_ELIM)       \
	MAPPER(NOT_EQUIV_ELIM)   \
	MAPPER(XOR_ELIM)         \
	MAPPER(NOT_XOR_ELIM)     \
	MAPPER(ITE_ELIM)         \
	MAPPER(NOT_ITE_ELIM)     \
	MAPPER(NOT_AND)          \
	MAPPER(CNF_AND_POS)      \
	MAPPER(CNF_AND_NEG)      \
	MAPPER(CNF_OR_POS)       \
	MAPPER(CNF_OR_NEG)       \
	MAPPER(CNF_IMPLIES_POS)  \
	MAPPER(CNF_IMPLIES_NEG)  \
	MAPPER(CNF_EQUIV_POS)    \
	MAPPER(CNF_EQUIV_NEG)    \
	MAPPER(CNF_XOR_POS)      \
	MAPPER(CNF_XOR_NEG)      \
	MAPPER(CNF_ITE_POS)      \
	MAPPER(CNF_ITE_NEG)      \
	MAPPER(ITE_EQ)

#define BCF_BV_RULES(MAPPER) MAPPER(BITBLAST)

/* Compile-time validation that rule sets match uapi definitions */
#define BCF_RULE_CHECK_MAPPER(_r) ___BCF_RULE_CHECK_##_r,
// clang-format off
#define BCF_RULE_STATIC_CHECK(_set)					\
	enum ___##_set {						\
		___BCF_RULE_CHECK_##_set = 0,				\
		_set(BCF_RULE_CHECK_MAPPER)				\
		___MAX_BCF_RULE_CHECK_##_set,				\
	};								\
	static_assert(___MAX_BCF_RULE_CHECK_##_set - 1 == __MAX_##_set)
// clang-format on
BCF_RULE_STATIC_CHECK(BCF_CORE_RULES);
BCF_RULE_STATIC_CHECK(BCF_BOOL_RULES);
BCF_RULE_STATIC_CHECK(BCF_BV_RULES);
#undef BCF_RULE_STATIC_CHECK
#undef BCF_RULE_CHECK_MAPPER

#define BCF_RULE_NAME(rule) BCF_RULE_##rule
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
	u8 pm_cnt = step->premise_cnt;
	struct bcf_expr_ref *fact;
	struct bcf_expr *premise;
	u32 premise_id;
	int err;

	goto *checkers[rule];

ASSUME:
	/* Assume can only appear once in the first step */
	return -EINVAL;

INSTANTIATION:
	/* TODO: implement lemma application */
	return -ENOTSUPP;

REFL: /* A ⊢ A = A */
{
	premise_id = get_pm_id(st, step, 0);
	fact = build_equiv(st, premise_id, premise_id);
	return set_step_fact(st, fact);
}

SYMM: /* A = B ⊢ B = A */
{
	struct bcf_expr *eq;

	premise = get_pm(st, step, 0);
	eq = premise;
	if (is_not(premise->code))
		eq = id_to_expr(st, premise->args[0]);
	ENSURE(is_equiv(eq->code));

	fact = build_equiv(st, eq->args[1], eq->args[0]);
	if (fact && is_not(premise->code))
		fact = add_not(st, fact->id);

	return set_step_fact(st, fact);
}

TRANS: /* A = B, B = C ⊢ A = C */
{
	u32 lhs_id = 0, rhs_id = 0;
	bool first = true;

	bcf_for_each_pm_expr(premise, step, st) {
		ENSURE(is_equiv(premise->code));

		if (first) {
			lhs_id = premise->args[0];
			rhs_id = premise->args[1];
			first = false;
		} else {
			/* Transitivity chain: current LHS matches previous RHS */
			if (expr_id_equiv(st, rhs_id, premise->args[0]) != 1)
				return -EINVAL;
			rhs_id = premise->args[1];
		}
	}

	fact = build_equiv(st, lhs_id, rhs_id);
	return set_step_fact(st, fact);
}

CONG: /* A = B ⊢ f(A) = f(B) */
{
	struct bcf_expr *expr_buf = get_expr_buf(st);
	struct bcf_expr_ref *lhs, *rhs;
	u32 *args;

	/* The first param encodes the expr (function) to apply*/
	*(u32 *)expr_buf = step->args[pm_cnt];

	/* Build expression with LHS arguments */
	args = expr_buf->args;
	bcf_for_each_pm_expr(premise, step, st) {
		ENSURE(is_equiv(premise->code));
		*args++ = premise->args[0];
	}
	if ((err = check_expr_type(st, expr_buf)) != 0)
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

	fact = add_equiv(st, lhs->id, rhs->id);
	return set_step_fact(st, fact);
}

TRUE_INTRO: /* A ⊢ A = True */
{
	premise_id = get_pm_id(st, step, 0);
	fact = build_equiv(st, premise_id, st->true_expr);
	return set_step_fact(st, fact);
}

TRUE_ELIM: /* A = True ⊢ A */
{
	premise = get_pm(st, step, 0);
	ENSURE(is_equiv(premise->code));
	ENSURE(expr_id_equiv(st, premise->args[1], st->true_expr) == 1);

	__set_step_fact(st, NULL, premise->args[0]);
	return 0;
}

FALSE_INTRO: /* ¬A ⊢ A = False */
{
	premise = get_pm(st, step, 0);
	ENSURE(is_not(premise->code));

	fact = build_equiv(st, premise->args[0], st->false_expr);
	return set_step_fact(st, fact);
}

FALSE_ELIM: /* A = False ⊢ ¬A */
{
	premise = get_pm(st, step, 0);
	ENSURE(is_equiv(premise->code));
	ENSURE(expr_id_equiv(st, premise->args[1], st->false_expr) == 1);

	fact = build_not(st, premise->args[0]);
	return set_step_fact(st, fact);
}

bad_rule:
	BUG();
	return -EFAULT;
}

static int equiv_elim(struct bcf_checker_state *st, struct bcf_expr *premise,
		      u32 lit)
{
	struct bcf_expr_ref *not_expr, *fact;
	u32 e0, e1;

	ENSURE(lit == 0 || lit == 1);

	e0 = premise->args[0];
	e1 = premise->args[1];
	if (lit) {
		not_expr = build_not(st, e1);
		if (!not_expr)
			return -EINVAL;
		e1 = not_expr->id;
		expr_id_get(st, e0);
	} else {
		not_expr = build_not(st, e0);
		if (!not_expr)
			return -EINVAL;
		e0 = not_expr->id;
		expr_id_get(st, e1);
	}

	fact = add_disj(st, e0, e1);
	return set_step_fact(st, fact);
}

static int not_equiv_elim(struct bcf_checker_state *st,
			  struct bcf_expr *premise, u32 lit)
{
	struct bcf_expr_ref *not_expr, *fact;
	u32 e0, e1;

	ENSURE(lit == 0 || lit == 1);

	e0 = premise->args[0];
	e1 = premise->args[1];
	if (lit) {
		not_expr = build_not(st, e0);
		if (!not_expr)
			return -EINVAL;
		e0 = not_expr->id;

		not_expr = build_not(st, e1);
		if (!not_expr)
			return -EINVAL;
		e1 = not_expr->id;
	} else {
		expr_id_get(st, e0);
		expr_id_get(st, e1);
	}

	fact = add_disj(st, e0, e1);
	return set_step_fact(st, fact);
}

static int __cnf_equiv_pos(struct bcf_checker_state *st, u32 arg, u32 lit,
			   bool xor)
{
	struct bcf_expr_ref *not_expr, *fact;
	struct bcf_expr *arg_expr;
	u8 code = xor ? (BCF_BOOL | BCF_XOR) : (BCF_BOOL | BPF_JEQ);
	u32 e0, e1, e2;

	arg_expr = get_arg_expr(st, arg);
	ENSURE(arg_expr && arg_expr->code == code);
	ENSURE(lit == 0 || lit == 1);

	e0 = arg;
	if (!xor) {
		not_expr = build_not(st, arg);
		CHECK_PTR(not_expr);
		e0 = not_expr->id;
	}

	e1 = arg_expr->args[0];
	e2 = arg_expr->args[1];
	if (lit) {
		not_expr = build_not(st, e2);
		CHECK_PTR(not_expr);
		e2 = not_expr->id;
	} else {
		not_expr = build_not(st, e1);
		CHECK_PTR(not_expr);
		e1 = not_expr->id;
	}

	fact = add_disj3(st, e0, e1, e2);
	return set_step_fact(st, fact);
}

static int cnf_equiv_pos(struct bcf_checker_state *st, u32 arg, u32 lit)
{
	return __cnf_equiv_pos(st, arg, lit, false);
}

static int cnf_xor_neg(struct bcf_checker_state *st, u32 arg, u32 lit)
{
	return __cnf_equiv_pos(st, arg, lit, true);
}

static int __cnf_equiv_neg(struct bcf_checker_state *st, u32 arg, u32 lit,
			   bool xor)
{
	struct bcf_expr_ref *not_expr, *fact;
	struct bcf_expr *arg_expr;
	u32 e0, e1, e2;

	arg_expr = get_arg_expr(st, arg);
	ENSURE(arg_expr);
	if (xor)
		ENSURE(is_xor(arg_expr->code));
	else
		ENSURE(is_equiv(arg_expr->code));
	ENSURE(lit == 0 || lit == 1);

	e0 = arg;
	if (xor) { /* equiv_neg == xor_pos */
		not_expr = build_not(st, arg);
		CHECK_PTR(not_expr);
		e0 = not_expr->id;
	}

	e1 = arg_expr->args[0];
	e2 = arg_expr->args[1];
	if (lit) {
		not_expr = build_not(st, e1);
		CHECK_PTR(not_expr);
		e1 = not_expr->id;
		not_expr = build_not(st, e2);
		CHECK_PTR(not_expr);
		e2 = not_expr->id;
	}
	fact = add_disj3(st, e0, e1, e2);
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

#define INLINE_ENCODE_PM_CNT 4
#define U32_PER_LONG (sizeof(unsigned long) / sizeof(u32))

/* Parse the polarity and literal indices from the step parameters.
 * Supports both inline and list encoding.
 */
static int parse_resolution_params(struct bcf_checker_state *st,
				   struct bcf_proof_step *step,
				   unsigned long *pol_bitmap, u32 **lits_out)
{
	u32 pm_cnt = step->premise_cnt;
	u32 lit_cnt = pm_cnt - 1;
	struct bcf_expr *pol_list, *lit_list;
	u32 pol_vlen, bits;

	if (pm_cnt <= INLINE_ENCODE_PM_CNT) {
		u32 arg = step->args[pm_cnt];
		unsigned long pols = arg >> 24;
		u32 i, mask = GENMASK(lit_cnt - 1, 0);
		u32 *lits = *lits_out;

		arg &= GENMASK(23, 0);
		for (i = 0; i < lit_cnt; i++) {
			u32 lit_idx = (u8)arg;
			if (!get_bool_arg(st, lit_idx))
				return -EINVAL;
			*lits++ = lit_idx;
			arg >>= 8;
		}
		if (arg)
			return -EINVAL; /* Reserved bits used */
		if (pols & ~mask)
			return -EINVAL; /* Reserved bits used */
		bitmap_copy(pol_bitmap, &pols, lit_cnt);
		return 0;
	}

	/* List encoding */
	pol_list = get_list_arg(st, step->args[pm_cnt]);
	pol_vlen = bitmap_size(lit_cnt) * U32_PER_LONG;
	bits = pol_vlen * 32;

	ENSURE(pol_list && pol_list->vlen == pol_vlen);
	ENSURE(find_next_bit((void *)pol_list->args, bits, lit_cnt) == bits);
	bitmap_copy(pol_bitmap, (void *)pol_list->args, lit_cnt);

	lit_list = get_list_arg(st, step->args[pm_cnt + 1]);
	ENSURE(lit_list && lit_list->vlen == lit_cnt);
	bcf_for_each_arg(arg, lit_list)
		ENSURE(get_bool_arg(st, arg));
	*lits_out = lit_list->args;
	return 0;
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

static int copy_expr_args(struct bcf_expr *dst, struct bcf_expr *src)
{
	return __copy_expr_args(dst, src, false);
}

static int append_expr_args(struct bcf_expr *dst, struct bcf_expr *src)
{
	return __copy_expr_args(dst, src, true);
}

static int copy_literals(struct bcf_checker_state *st, struct bcf_expr *lits,
			 u32 clause, struct bcf_expr *pivot)
{
	struct bcf_expr *clause_expr;

	clause_expr = id_to_expr(st, clause);
	if (is_disj(clause_expr->code)) {
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
		u32 rest;

		ret = expr_equiv(st, lit, pivot);
		if (ret < 0)
			return ret;
		if (ret == 0)
			continue;

		rest = lits->vlen - (i + 1);
		if (rest)
			memmove(&lits->args[i], &lits->args[i + 1],
				sizeof(u32) * rest);
		lits->vlen--;
		break;
	}
	return 0;
}

static void get_pivots(struct bcf_checker_state *st, struct bcf_expr **pivots,
		       u32 pivot, bool pol)
{
	st->not_expr = BCF_BOOL_NOT(pivot);
	pivots[0] = get_arg_expr(st, pivot);
	pivots[1] = (void *)&st->not_expr;
	if (!pol)
		swap(pivots[0], pivots[1]);
	return;
}

static int chain_resolution(struct bcf_checker_state *st,
			    struct bcf_proof_step *step)
{
	unsigned long pols_buf[bitmap_size(U8_MAX)] = { 0 };
	u32 lits_buf[INLINE_ENCODE_PM_CNT - 1];
	struct bcf_expr_buf rhs_lits_buf = { 0 };
	struct bcf_expr *rhs_lits = (void *)&rhs_lits_buf;
	struct bcf_expr *pivots[2];
	unsigned long *pols = pols_buf;
	u32 pm_cnt = step->premise_cnt;
	u32 lit_cnt = pm_cnt - 1;
	u32 *lits = lits_buf;
	u32 lhs_pm, rhs_pm;
	struct bcf_expr *lhs_lits;
	struct bcf_expr_ref *fact;
	int err;

	/* Parse polarity and pivots */
	err = parse_resolution_params(st, step, pols, &lits);
	if (err)
		return err;

	/* Set up the first clause */
	lhs_lits = get_expr_buf(st);
	lhs_pm = get_pm_id(st, step, 0);
	get_pivots(st, pivots, lits[0], test_bit(0, pols));
	err = copy_literals(st, lhs_lits, lhs_pm, pivots[0]);
	if (err)
		return err;

	for (u32 i = 0, rhs = 1; i < lit_cnt; i++, rhs++) {
		rhs_pm = get_pm_id(st, step, rhs);
		get_pivots(st, pivots, lits[i], test_bit(i, pols));

		err = elim_pivot(st, lhs_lits, pivots[0]);
		err = err ?: copy_literals(st, rhs_lits, rhs_pm, pivots[1]);
		err = err ?: elim_pivot(st, rhs_lits, pivots[1]);
		err = err ?: append_expr_args(lhs_lits, rhs_lits);
		if (err)
			return err;
	}

	if (pm_cnt == 2 && lhs_lits->vlen < 2) {
		u32 fact_id;

		fact_id = st->false_expr;
		if (lhs_lits->vlen == 1)
			fact_id = lhs_lits->args[0];

		__set_step_fact(st, NULL, fact_id);
		return 0;
	}

	ENSURE(lhs_lits->vlen >= 2);
	lhs_lits->code = BCF_BOOL | BCF_DISJ;
	fact = clone_expr(st, lhs_lits);
	return set_step_fact(st, fact);
}

/* The dup_pair_list is a packed byte array encoding duplicate pairs for factoring.
 * Each entry has the format:
 *   (pair_len, uniq_idx, dup_idx0, dup_idx1, ..., dup_idxN)
 * where:
 *   - pair_len: the number of indices in this pair (including uniq_idx and all dup_idx)
 *   - uniq_idx: the index of the unique literal in the clause
 *   - dup_idx*: indices of literals that are duplicates of uniq_idx
 *
 * The list is a sequence of such entries, e.g.:
 *   [pair_len, uniq0, dup0, dup1, ..., pair_len, uniq1, dup0, ...]
 *
 * Requirements:
 *   - The total number of bytes used by all pairs is leq than vlen (cnt * 4).
 *   - All unused bytes in the array must be zero.
 *   - uniq indices must be strictly increasing (uniq0 < uniq1 < ...).
 *   - For each pair, uniq_idx < dup_idx0 < dup_idx1 < ... (all indices strictly increasing).
 *   - For each duplicate, premise->args[uniq_idx] and premise->args[dup_idx*] must be equivalent
 *     (i.e., expr_id_equiv(premise->args[uniq_idx], premise->args[dup_idx*]) == 1).
 *   - For each duplicate index, set the corresponding bit in the dups_bitmap.
 */
static int parse_dup_pairs(struct bcf_checker_state *st,
			   struct bcf_expr *premise, u32 *params, u32 cnt,
			   unsigned long *dups_bitmap)
{
	u8 *dup_pair_list = (void *)params;
	u32 vlen = cnt * 4, pre_uniq;
	u32 *args = premise->args;
	u32 idx = 0, dup_cnt = 0;
	bool first = true;

	while (idx < vlen) {
		u32 pair_len = dup_pair_list[idx++]; /* move to the pair */
		u8 uniq, *dups;

		if (!pair_len)
			break;

		ENSURE(pair_len >= 2);
		ENSURE(idx + pair_len <= vlen);

		uniq = dup_pair_list[idx];
		ENSURE(uniq < premise->vlen);
		if (first)
			first = false;
		else
			ENSURE(uniq > pre_uniq);

		dups = &dup_pair_list[idx + 1];
		for (u32 i = 0; i < pair_len - 1; i++) {
			ENSURE(dups[i] < premise->vlen && dups[i] > uniq);
			ENSURE(expr_id_equiv(st, args[uniq], args[dups[i]]) ==
			       1);
			set_bit(dups[i], dups_bitmap);
			dup_cnt++;
		}

		pre_uniq = uniq;
		idx += pair_len;
	}

	ENSURE(dup_cnt);
	if (idx != vlen)
		ENSURE(!memchr_inv(&dup_pair_list[idx], 0, vlen - idx + 1));

	return 0;
}

static int __cmp_u32(const void *a, const void *b)
{
	return *(u32 *)a - *(u32 *)b;
}

static bool multiset_equal(const u32 *a, const u32 *b, u8 len)
{
	u32 buf_a[U8_MAX], buf_b[U8_MAX];

	memcpy(buf_a, a, sizeof(u32) * len);
	memcpy(buf_b, b, sizeof(u32) * len);
	sort(buf_a, len, sizeof(u32), __cmp_u32, NULL);
	sort(buf_b, len, sizeof(u32), __cmp_u32, NULL);

	return !memcmp(buf_a, buf_b, sizeof(u32) * len);
}

static int apply_bool_rule(struct bcf_checker_state *st,
			   struct bcf_proof_step *step)
{
	DEFINE_JUMP_TABLE(BCF_BOOL_RULES);
	u16 pm_cnt = step->premise_cnt, param_cnt = step->param_cnt;
	u16 rule = BCF_STEP_RULE(step->rule);
	struct bcf_expr *premise, *expr_buf, *arg_expr;
	struct bcf_expr_ref *fact, *not_expr;
	u32 premise_id;

	goto *checkers[rule];

RESOLUTION: /* (A ∨ l), (¬l ∨ B) ⊢ (A ∨ B) */
{
	ENSURE(pm_cnt >= 2);
	/* pol and lit are encoded in an u32 if pm_cnt less/equal then 4 */
	ENSURE(pm_cnt > 4 || param_cnt == 1);
	/* otherwise, pol and L are encoded by two list parameters */
	ENSURE(pm_cnt <= 4 || param_cnt == 2);

	return chain_resolution(st, step);
}

FACTORING: /* (A ∨ l ∨ l) ⊢ (A ∨ l) */
{
	unsigned long dups[bitmap_size(U8_MAX)] = { 0 };
	struct bcf_expr *dedupped;
	int err;

	ENSURE(pm_cnt == 1 && param_cnt);

	premise = get_pm(st, step, 0);
	ENSURE(is_disj(premise->code));

	err = parse_dup_pairs(st, premise, &step->args[1], param_cnt, dups);
	if (err)
		return err;

	dedupped = get_expr_buf(st);
	dedupped->code = BCF_BOOL | BCF_DISJ;
	for (u32 i = 0; i < premise->vlen; i++) {
		if (test_bit(i, dups))
			continue;
		dedupped->args[dedupped->vlen++] = premise->args[i];
	}

	ENSURE(dedupped->vlen >= 2);
	fact = clone_expr(st, dedupped);
	return set_step_fact(st, fact);
}

REORDERING: /* (l₁ ∨ ... ∨ lₙ) ⊢ (l_{π(1)} ∨ ... ∨ l_{π(n)}) */
{
	struct bcf_expr *roe;

	ENSURE(pm_cnt == 1 && param_cnt == 1);

	premise = get_pm(st, step, 0);
	roe = get_arg_expr(st, step->args[1]);
	ENSURE(roe && expr_node_equiv(premise, roe));

	if (!is_disj(premise->code)) {
		ENSURE(expr_equiv(st, premise, roe) == 1);
		__set_step_fact(st, NULL, step->args[1]);
		return 0;
	}

	ENSURE(multiset_equal(premise->args, roe->args, premise->vlen));
	__set_step_fact(st, NULL, step->args[1]);
	return 0;
}

SPLIT: /* ⊢ A ∨ ¬A */
{
	struct bcf_expr_ref *not;
	u32 arg;

	ENSURE(pm_cnt == 0 && param_cnt == 1);

	arg = step->args[0];
	ENSURE(is_valid_arg(st, arg));
	ENSURE(is_bool(st->exprs[arg].code));

	not = add_not(st, arg);
	CHECK_PTR(not);
	fact = add_disj(st, arg, not->id);
	return set_step_fact(st, fact);
}

EQ_RESOLVE: /* (A, A = B) ⊢ B */
{
	ENSURE(pm_cnt == 2 && param_cnt == 0);

	premise_id = get_pm_id(st, step, 0);
	premise = get_pm(st, step, 1);
	ENSURE(is_equiv(premise->code));
	ENSURE(expr_id_equiv(st, premise_id, premise->args[0]) == 1);

	__set_step_fact(st, NULL, premise->args[1]);
	return 0;
}

MODUS_PONENS: /* A, (A ⇒ B) ⊢ B */
{
	ENSURE(pm_cnt == 2 && param_cnt == 0);

	premise_id = get_pm_id(st, step, 0);
	premise = get_pm(st, step, 1);
	ENSURE(is_implies(premise->code));
	ENSURE(expr_id_equiv(st, premise_id, premise->args[0]) == 1);

	__set_step_fact(st, NULL, premise->args[1]);
	return 0;
}

NOT_NOT_ELIM: /* ¬¬A ⊢ A */
{
	ENSURE(pm_cnt == 1 && param_cnt == 0);

	premise = get_pm(st, step, 0);
	ENSURE(is_not(premise->code));
	premise = id_to_expr(st, premise->args[0]);
	ENSURE(is_not(premise->code));

	__set_step_fact(st, NULL, premise->args[0]);
	return 0;
}

CONTRA: /* A, ¬A ⊢ ⊥ */
{
	ENSURE(pm_cnt == 2 && param_cnt == 0);

	premise_id = get_pm_id(st, step, 0);
	premise = get_pm(st, step, 1);
	ENSURE(is_not(premise->code));
	ENSURE(expr_id_equiv(st, premise_id, premise->args[0]) == 1);

	__set_step_fact(st, NULL, st->false_expr);
	return 0;
}

AND_ELIM: /* (A ∧ B) ⊢ A */
{
	u32 clause;

	ENSURE(pm_cnt == 1 && param_cnt == 1);

	premise = get_pm(st, step, 0);
	clause = step->args[1];
	ENSURE(is_conj(premise->code));
	ENSURE(clause < premise->vlen);

	__set_step_fact(st, NULL, premise->args[clause]);
	return 0;
}

AND_INTRO: /* A, B ⊢ (A ∧ B) */
{
	u32 *clauses;

	ENSURE(pm_cnt == 2 && param_cnt == 0);

	if (pm_cnt == 1) {
		premise_id = get_pm_id(st, step, 0);
		__set_step_fact(st, NULL, premise_id);
		return 0;
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

	premise = get_pm(st, step, 0);
	ENSURE(is_not(premise->code));
	premise = id_to_expr(st, premise->args[0]);
	ENSURE(is_disj(premise->code));

	lit = step->args[1];
	ENSURE(lit < premise->vlen);

	fact = build_not(st, premise->args[lit]);
	return set_step_fact(st, fact);
}

IMPLIES_ELIM: /* (A ⇒ B) ⊢ ¬A ∨ B */
{
	struct bcf_expr_ref *not;

	ENSURE(pm_cnt == 1 && param_cnt == 0);

	premise = get_pm(st, step, 0);
	ENSURE(is_implies(premise->code));
	premise_id = premise->args[1];
	not = build_not(st, premise->args[0]);
	CHECK_PTR(not);
	expr_id_get(st, premise_id); /* inc ref */
	fact = add_disj(st, not->id, premise_id);
	return set_step_fact(st, fact);
}

NOT_IMPLIES_ELIM: /* ¬(A ⇒ B) ⊢ A ∧ ¬B */
{
	u32 idx;

	ENSURE(pm_cnt == 1 && param_cnt == 1);

	idx = step->args[1];
	ENSURE(idx == 0 || idx == 1);

	premise = get_pm(st, step, 0);
	ENSURE(is_not(premise->code));
	premise = id_to_expr(st, premise->args[0]);
	ENSURE(is_implies(premise->code));

	if (idx == 0) {
		__set_step_fact(st, NULL, premise->args[0]);
		return 0;
	} else {
		fact = build_not(st, premise->args[1]);
		return set_step_fact(st, fact);
	}
}

EQUIV_ELIM: /* (A ⇔ B) ⊢ (¬A ∨ B) ∧ (A ∨ ¬B) */
{
	ENSURE(pm_cnt == 1 && param_cnt == 1);

	premise = get_pm(st, step, 0);
	ENSURE(is_equiv(premise->code));
	return equiv_elim(st, premise, step->args[1]);
}

NOT_EQUIV_ELIM: /* ¬(A ⇔ B) ⊢ (A ∨ B) ∧ (¬A ∨ ¬B) */
{
	ENSURE(pm_cnt == 1 && param_cnt == 1);

	premise = get_pm(st, step, 0);
	ENSURE(is_not(premise->code));
	premise = id_to_expr(st, premise->args[0]);
	ENSURE(is_equiv(premise->code));
	return not_equiv_elim(st, premise, step->args[1]);
}

XOR_ELIM: /* (A ⊕ B) ⊢ (A ∨ B) ∧ (¬A ∨ ¬B) */
{
	ENSURE(pm_cnt == 1 && param_cnt == 1);

	premise = get_pm(st, step, 0);
	ENSURE(is_xor(premise->code));
	return not_equiv_elim(st, premise, step->args[1]);
}

NOT_XOR_ELIM: /* ¬(A ⊕ B) ⊢ (A ∨ ¬B) ∧ (¬A ∨ B) */
{
	u32 lit;

	ENSURE(pm_cnt == 1 && param_cnt == 1);

	premise = get_pm(st, step, 0);
	ENSURE(is_not(premise->code));
	premise = id_to_expr(st, premise->args[0]);
	ENSURE(is_xor(premise->code));

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

	premise = get_pm(st, step, 0);
	ENSURE(is_ite(premise->code));
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
		not_expr = build_not(st, premise->args[0]);
		CHECK_PTR(not_expr);
		e0 = not_expr->id;
		e1 = premise->args[1];
		expr_id_get(st, e1);
	}
	fact = add_disj(st, e0, e1);
	return set_step_fact(st, fact);
}

NOT_ITE_ELIM: /* ¬(C ? A : B) ⊢ (¬C ∨ ¬A) ∧ (C ∨ ¬B) */
{
	struct bcf_expr_ref *not_c, *not_a, *not_b;
	u32 lit, e0, e1;

	ENSURE(pm_cnt == 1 && param_cnt == 1);

	premise = get_pm(st, step, 0);
	ENSURE(is_not(premise->code));
	premise = id_to_expr(st, premise->args[0]);
	ENSURE(is_ite(premise->code));

	lit = step->args[1];
	ENSURE(lit == 0 || lit == 1);

	if (lit) {
		/* C ∨ ¬B */
		e0 = premise->args[0];
		expr_id_get(st, e0);

		not_b = build_not(st, premise->args[2]);
		CHECK_PTR(not_b);
		e1 = not_b->id;
	} else {
		/* ¬C ∨ ¬A */
		not_c = build_not(st, premise->args[0]);
		CHECK_PTR(not_c);
		e0 = not_c->id;

		not_a = build_not(st, premise->args[1]);
		CHECK_PTR(not_a);
		e1 = not_a->id;
	}

	fact = add_disj(st, e0, e1);
	return set_step_fact(st, fact);
}

NOT_AND: /* ¬(A ∧ B) ⊢ (¬A ∨ ¬B) */
{
	u32 *args;

	ENSURE(pm_cnt == 1 && param_cnt == 0);

	premise = get_pm(st, step, 0);
	ENSURE(is_not(premise->code));
	premise = id_to_expr(st, premise->args[0]);
	ENSURE(is_conj(premise->code));

	fact = alloc_expr(st, premise->vlen);
	CHECK_PTR(fact);

	fact->expr.code = BCF_BOOL | BCF_DISJ;
	args = fact->expr.args;
	bcf_for_each_arg(arg, premise) {
		not_expr = build_not(st, arg);
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
	ENSURE(arg_expr && is_conj(arg_expr->code));

	lit = step->args[1];
	ENSURE(lit < arg_expr->vlen);

	not_expr = build_not(st, step->args[0]);
	CHECK_PTR(not_expr);
	expr_id_get(st, arg_expr->args[lit]);

	fact = add_disj(st, not_expr->id, arg_expr->args[lit]);
	return set_step_fact(st, fact);
}

CNF_AND_NEG: /* (A ∧ B) ∨ ¬A ∨ ¬B */
{
	u32 *args;

	ENSURE(!pm_cnt && param_cnt == 1);

	arg_expr = get_arg_expr(st, step->args[0]);
	ENSURE(arg_expr && is_conj(arg_expr->code) && arg_expr->vlen != U8_MAX);

	fact = alloc_expr(st, arg_expr->vlen + 1);
	CHECK_PTR(fact);

	fact->expr.code = BCF_BOOL | BCF_DISJ;
	args = fact->expr.args;
	*args++ = step->args[0]; /* static expr, skip get */
	bcf_for_each_arg(arg, arg_expr) {
		not_expr = build_not(st, arg);
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
	ENSURE(arg_expr && is_disj(arg_expr->code) && arg_expr->vlen != U8_MAX);

	not_expr = build_not(st, step->args[0]);
	CHECK_PTR(not_expr);

	fact = alloc_expr(st, arg_expr->vlen + 1);
	CHECK_PTR(fact);
	fact->expr.code = BCF_BOOL | BCF_DISJ;
	args = fact->expr.args;
	*args++ = not_expr->id;
	bcf_for_each_arg(arg, arg_expr) {
		expr_id_get(st, arg);
		*args++ = arg;
	}
	return set_step_fact(st, fact);
}

CNF_OR_NEG: /* (A ∨ B) ∨ ¬A */
{
	u32 term;

	ENSURE(!pm_cnt && param_cnt == 2);

	arg_expr = get_arg_expr(st, step->args[0]);
	ENSURE(arg_expr && is_disj(arg_expr->code));
	term = step->args[1];
	ENSURE(term < arg_expr->vlen);

	not_expr = build_not(st, arg_expr->args[term]);
	CHECK_PTR(not_expr);

	fact = add_disj(st, step->args[0], not_expr->id);
	return set_step_fact(st, fact);
}

CNF_IMPLIES_POS: /* (A ⇒ B) ∨ ¬A ∨ B */
{
	struct bcf_expr_ref *not_term;

	ENSURE(!pm_cnt && param_cnt == 1);

	arg_expr = get_arg_expr(st, step->args[0]);
	ENSURE(arg_expr && is_implies(arg_expr->code));

	not_expr = build_not(st, step->args[0]);
	CHECK_PTR(not_expr);
	not_term = build_not(st, arg_expr->args[0]);
	CHECK_PTR(not_term);

	fact = add_disj3(st, not_expr->id, not_term->id, arg_expr->args[1]);
	return set_step_fact(st, fact);
}

CNF_IMPLIES_NEG: /* (A ⇒ B) ∨ (A ∧ ¬B) */
{
	u32 lit, e0, e1;

	ENSURE(!pm_cnt && param_cnt == 2);

	arg_expr = get_arg_expr(st, step->args[0]);
	ENSURE(arg_expr && is_implies(arg_expr->code));
	lit = step->args[1];
	ENSURE(lit == 0 || lit == 1);

	e0 = step->args[0];
	e1 = arg_expr->args[0];
	if (lit) {
		not_expr = build_not(st, arg_expr->args[1]);
		CHECK_PTR(not_expr);
		e1 = not_expr->id;
	}
	fact = add_disj(st, e0, e1);
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
	ENSURE(arg_expr && is_ite(arg_expr->code));
	lit = step->args[1];

	e0 = step->args[0];
	not_expr = build_not(st, e0);
	CHECK_PTR(not_expr);
	e0 = not_expr->id;

	switch (lit) {
	case 0:
		e1 = arg_expr->args[0];
		e2 = arg_expr->args[1];
		not_expr = build_not(st, e1);
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

	fact = add_disj3(st, e0, e1, e2);
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
	ENSURE(arg_expr && is_ite(arg_expr->code));
	lit = step->args[1];

	e0 = step->args[0];

	switch (lit) {
	case 0:
		e1 = arg_expr->args[0];
		not_expr = build_not(st, e1);
		CHECK_PTR(not_expr);
		e1 = not_expr->id;

		e2 = arg_expr->args[1];
		not_expr = build_not(st, e2);
		CHECK_PTR(not_expr);
		e2 = not_expr->id;
		break;
	case 1:
		e1 = arg_expr->args[0];
		e2 = arg_expr->args[2];
		not_expr = build_not(st, e2);
		CHECK_PTR(not_expr);
		e2 = not_expr->id;
		break;
	case 2:
		e1 = arg_expr->args[1];
		e2 = arg_expr->args[2];
		not_expr = build_not(st, e1);
		CHECK_PTR(not_expr);

		e1 = not_expr->id;
		not_expr = build_not(st, e2);
		CHECK_PTR(not_expr);
		e2 = not_expr->id;
		break;
	default:
		return -EINVAL;
	}

	fact = add_disj3(st, e0, e1, e2);
	return set_step_fact(st, fact);
}

ITE_EQ: /* (C ? (C ? A : B) = A : (C ? A : B) = B) */
{
	struct bcf_expr_ref *eq_expr;
	u32 c, t0, t1, e1, e2;

	ENSURE(!pm_cnt && param_cnt == 1);

	arg_expr = get_arg_expr(st, step->args[0]);
	ENSURE(arg_expr && is_ite(arg_expr->code));

	c = step->args[0];
	t0 = arg_expr->args[1];
	t1 = arg_expr->args[2];

	eq_expr = add_equiv(st, c, t0);
	CHECK_PTR(eq_expr);
	e1 = eq_expr->id;

	eq_expr = add_equiv(st, c, t1);
	CHECK_PTR(eq_expr);
	e2 = eq_expr->id;

	fact = add_ite(st, c, e1, e2);
	return set_step_fact(st, fact);
}

bad_rule:
	return -EFAULT;
}

static bool is_bitof(struct bcf_checker_state *st, u32 id, u32 bit, u32 bv_id)
{
	struct bcf_expr *e = id_to_expr(st, id);

	return e->code == (BCF_BV | BCF_BITOF) && e->args[0] == bv_id &&
	       e->params == bit;
}

static bool is_not_of(struct bcf_checker_state *st, u32 not_id, u32 e_id)
{
	struct bcf_expr *not_expr = id_to_expr(st, not_id);

	return is_not(not_expr->code) && not_expr->args[0] == e_id;
}

static bool is_conj2(struct bcf_checker_state *st, u32 e_id)
{
	struct bcf_expr *expr = id_to_expr(st, e_id);

	return is_conj(expr->code) && expr->vlen == 2;
}

static bool is_disj2(struct bcf_checker_state *st, u32 e_id)
{
	struct bcf_expr *expr = id_to_expr(st, e_id);

	return is_disj(expr->code) && expr->vlen == 2;
}

static bool is_equiv_of(struct bcf_checker_state *st, u32 eq_id, u32 e0, u32 e1)
{
	struct bcf_expr *expr = id_to_expr(st, eq_id);

	return is_equiv(expr->code) && expr->args[0] == e0 &&
	       expr->args[1] == e1;
}

static int check_bb_term(struct bcf_checker_state *st, u32 term_id, u32 bbt_id)
{
	struct bcf_expr *term = id_to_expr(st, term_id);
	struct bcf_expr *bbt = id_to_expr(st, bbt_id);
	u8 op = BPF_OP(term->code);
	struct bcf_expr *bit;

	ENSURE(is_from_bool(bbt->code));

	if (op == BCF_VAR) {
		for (int i = 0; i < bbt->vlen; i++)
			ENSURE(is_bitof(st, bbt->args[i], i, term_id));

		return 0;
	}

	if (op == BCF_VAL) {
		u64 val = bv_val(term);

		bcf_for_each_arg_expr(i, bit, bbt, st) {
			ENSURE(test_bit(i, &val) ? is_true(bit) :
						   is_false(bit));
		}
		return 0;
	}

	if (op == BPF_NEG) {
		struct bcf_expr *sub_term = id_to_expr(st, term->args[0]);

		ENSURE(is_from_bool(sub_term->code));
		for (int i = 0; i < sub_term->vlen; i++)
			ENSURE(is_not_of(st, bbt->args[i], sub_term->args[i]));

		return 0;
	}

	return -ENOTSUPP;
}
/* Check bitblast bv-ult */
static int bb_ult(struct bcf_checker_state *st, struct bcf_expr *res, u32 *lhs,
		  u32 *rhs, u32 vlen, bool eq)
{
	struct bcf_expr *l, *r;
	int i;

	for (i = vlen - 1; i > 0; i--) {
		ENSURE(is_disj(res->code) && res->vlen == 2);
		ENSURE(is_conj2(st, res->args[0]));
		ENSURE(is_conj2(st, res->args[1]));

		r = id_to_expr(st, res->args[1]);
		ENSURE(is_not_of(st, r->args[0], lhs[i]));
		ENSURE(r->args[1] == rhs[i]);

		l = id_to_expr(st, res->args[0]);
		ENSURE(is_equiv_of(st, l->args[0], lhs[i], rhs[i]));

		res = id_to_expr(st, l->args[1]);
	}

	if (eq) {
		ENSURE(is_disj(res->code) && res->vlen == 2);
		ENSURE(is_equiv_of(st, res->args[1], lhs[0], rhs[0]));
		res = id_to_expr(st, res->args[0]);
	}

	ENSURE(is_conj(res->code) && res->vlen == 2);
	ENSURE(res->args[1] == rhs[0]);
	ENSURE(is_not_of(st, res->args[0], lhs[0]));

	return 0;
}

/* Check bitblast bv-slt */
static int bb_slt(struct bcf_checker_state *st, struct bcf_expr *res, u32 *lhs,
		  u32 *rhs, u32 vlen, bool eq)
{
	struct bcf_expr *sign_same, *neg_lhs;
	u32 sbit;

	if (vlen <= 1)
		return -EINVAL;

	sbit = vlen - 1;

	ENSURE(is_disj(res->code) && res->vlen == 2);
	ENSURE(is_conj2(st, res->args[0]));
	ENSURE(is_conj2(st, res->args[1]));

	neg_lhs = id_to_expr(st, res->args[1]);
	ENSURE(neg_lhs->args[0] == lhs[sbit]);
	ENSURE(is_not_of(st, neg_lhs->args[1], rhs[sbit]));

	sign_same = id_to_expr(st, res->args[0]);
	ENSURE(is_equiv_of(st, sign_same->args[0], lhs[sbit], rhs[sbit]));

	res = id_to_expr(st, res->args[1]);
	return bb_ult(st, res, lhs, rhs, vlen - 1, eq);
}

static int check_bb_atom(struct bcf_checker_state *st, struct bcf_expr *atom,
			 struct bcf_expr *bbt)
{
	u32 *lbits, *rbits, vlen, i;
	u8 op = BCF_OP(atom->code);
	bool eq = false;

	switch (op) {
	case BPF_JLE:
	case BPF_JSLE:
		eq = true;
		fallthrough;
	case BPF_JEQ:
	case BPF_JLT:
	case BPF_JSLT: {
		struct bcf_expr *lhs, *rhs;

		lhs = id_to_expr(st, atom->args[0]);
		rhs = id_to_expr(st, atom->args[1]);
		/* Must be already bitblasted term. */
		ENSURE(is_from_bool(lhs->code));
		ENSURE(is_from_bool(rhs->code));

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
		ENSURE(is_conj(bbt->code) && bbt->vlen == vlen);
		for (i = 0; i < bbt->vlen; i++)
			ENSURE(is_equiv_of(st, bbt->args[i], lbits[i],
					   rbits[i]));

		return 0;
	}

	if (op == BPF_JLT || op == BPF_JLE)
		return bb_ult(st, bbt, lbits, rbits, vlen, eq);

	/* BPF_JSLT || BPF_JSLE */
	return bb_slt(st, bbt, lbits, rbits, vlen, eq);
}

static int apply_bv_rule(struct bcf_checker_state *st,
			 struct bcf_proof_step *step)
{
	struct bcf_expr *bbt_eq, *bv, *bbt;
	int err;

	ENSURE(BCF_STEP_RULE(step->rule) == BCF_RULE_BITBLAST);
	ENSURE(!step->premise_cnt && step->param_cnt == 1);

	/* bbt_eq must be: bv (term/atom) = bbt;
	 * A bv term a bv expr of bv type, e.g., (+ bv0 bv1);
	 * A bv atom is a bv predicate of bool types, e.g., (> bv0 bv1);
	 * Bitblasted terms (atom) are called bbt for short.
	 */
	bbt_eq = get_arg_expr(st, step->args[0]);
	CHECK_PTR(bbt_eq);
	ENSURE(is_equiv(bbt_eq->code));

	/* Check the bitblasted term bbt is equiv to bv. */
	bv = id_to_expr(st, bbt_eq->args[0]);
	bbt = id_to_expr(st, bbt_eq->args[1]);
	if (is_bv(bv->code))
		/* bv term to bbt */
		err = check_bb_term(st, bbt_eq->args[0], bbt_eq->args[1]);
	else if (is_bool(bv->code))
		/* bv atom to bbt */
		err = check_bb_atom(st, bv, bbt);
	else
		err = -EINVAL;
	ENSURE(!err);

	__set_step_fact(st, NULL, step->args[0]);
	return 0;
}

#undef DEFINE_JUMP_TABLE
#undef RULE_TBL
#undef BCF_RULE_NAME

static int apply_rules(struct bcf_checker_state *st)
{
	struct bcf_expr *fact;
	int err;

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
		else
			err = -EFAULT;
		if (err)
			return err;

		st->cur_step_idx += STEP_SZ(step);
		st->cur_step++;
	}

	/* The last step muct refute the goal by concluding `false` */
	fact = st->step_state[st->step_cnt - 1].fact;
	if (!expr_node_equiv(fact, &BCF_BOOL_FALSE))
		return -EINVAL;

	return 0;
}

static int check_hdr(struct bcf_proof_header *hdr, union bpf_attr *attr,
		     bpfptr_t bcf_buf)
{
	size_t proof_size = attr->bcf_buf_true_size;
	size_t expr_size, step_size, sz;

	if (proof_size > attr->bcf_buf_size ||
	    proof_size > MAX_BCF_PROOF_SIZE || proof_size <= sizeof(*hdr) ||
	    proof_size % sizeof(u32))
		return -EINVAL;

	if (copy_from_bpfptr(hdr, bcf_buf, sizeof(*hdr)))
		return -EFAULT;

	if (hdr->magic != BCF_MAGIC || !hdr->expr_cnt || !hdr->step_cnt)
		return -EINVAL;

	expr_size = size_mul(hdr->expr_cnt, sizeof(struct bcf_expr));
	step_size = size_mul(hdr->step_cnt, sizeof(struct bcf_proof_step));
	if (check_add_overflow(expr_size, step_size, &sz))
		return -EINVAL;
	if (proof_size != sizeof(*hdr) + sz)
		return -EINVAL;

	return 0;
}

int bcf_check_proof(struct bpf_verifier_env *verifier_env, union bpf_attr *attr,
		    bpfptr_t uattr)
{
	bpfptr_t bcf_buf = make_bpfptr(attr->bcf_buf, uattr.is_kernel);
	struct bcf_checker_state *st __free(free_checker) = NULL;
	struct bcf_proof_header hdr;
	int err;

	err = check_hdr(&hdr, attr, bcf_buf);
	if (err)
		return err;

	st = kzalloc(sizeof(*st), GFP_KERNEL);
	if (!st)
		return -ENOMEM;
	st->verifier_env = verifier_env;
	xa_init(&st->expr_id_map);

	bpfptr_add(&bcf_buf, sizeof(struct bcf_proof_header));
	err = check_exprs(st, bcf_buf, hdr.expr_cnt);

	bpfptr_add(&bcf_buf, hdr.expr_cnt * sizeof(struct bcf_expr));
	err = err ?: check_steps(st, bcf_buf, hdr.step_cnt);
	err = err ?: apply_rules(st);

	return err;
}
