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
#include <linux/bpf.h>
#include <linux/bcf_checker.h>
#include <linux/xarray.h>

#include "test_utils.h"

#include "bcf_rewrite_dsl.h"

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
#define BCF_BOOL_BITOF(bit, arg)              \
	((struct bcf_expr_unary){             \
		.code = BCF_BOOL | BCF_BITOF, \
		.vlen = 1,                    \
		.params = (u8)(bit),          \
		.arg0 = (arg),                \
	})

// Bitvector if-then-else (ITE) macro, matching BCF_BOOL_ITE style
#ifndef BCF_BV_ITE
#define BCF_BV_ITE(width, cond, then_arg, else_arg) \
	((struct bcf_expr_ternary){                 \
		.code = BCF_BV | BCF_ITE,           \
		.vlen = 3,                          \
		.params = (width),                  \
		.arg0 = (cond),                     \
		.arg1 = (then_arg),                 \
		.arg2 = (else_arg),                 \
	})
#endif

// --- Extra macros for test variadic/ternary/bitvector/boolean expressions ---
#ifndef BCF_LIST_BV
#define BCF_LIST_BV(n, ...)                 \
	((struct bcf_expr){                 \
		.code = BCF_LIST | BCF_VAL, \
		.vlen = (n),                \
		.params = (BCF_BV),         \
		.args = { __VA_ARGS__ },    \
	})
#endif

#ifndef BCF_BOOL_CONJ
#define BCF_BOOL_CONJ(n, ...)                \
	((struct bcf_expr){                  \
		.code = BCF_BOOL | BCF_CONJ, \
		.vlen = (n),                 \
		.params = 0,                 \
		.args = { __VA_ARGS__ },     \
	})
#endif

#ifndef BCF_BOOL_DISJ
#define BCF_BOOL_DISJ(n, ...)                \
	((struct bcf_expr){                  \
		.code = BCF_BOOL | BCF_DISJ, \
		.vlen = (n),                 \
		.params = 0,                 \
		.args = { __VA_ARGS__ },     \
	})
#endif

#ifndef BCF_BV_BBT
#define BCF_BV_BBT(n, width, ...)               \
	((struct bcf_expr){                     \
		.code = BCF_BV | BCF_FROM_BOOL, \
		.vlen = (n),                    \
		.params = (width),              \
		.args = { __VA_ARGS__ },        \
	})
#endif

#ifndef BCF_BV_CONCAT
#define BCF_BV_CONCAT(n, width, ...)         \
	((struct bcf_expr){                  \
		.code = BCF_BV | BCF_CONCAT, \
		.vlen = (n),                 \
		.params = (width),           \
		.args = { __VA_ARGS__ },     \
	})
#endif

#ifndef BCF_BV_EXTRACT
#define BCF_BV_EXTRACT(start, end, arg)             \
	((struct bcf_expr_unary){                   \
		.code = BCF_BV | BCF_EXTRACT,       \
		.vlen = 1,                          \
		.params = (((start) << 8) | (end)), \
		.arg0 = (arg),                      \
	})
#endif

#ifndef BCF_BV_VAR8
#define BCF_BV_VAR8                       \
	((struct bcf_expr){               \
		.code = BCF_BV | BCF_VAR, \
		.vlen = 0,                \
		.params = 8,              \
	})
#endif

#ifndef BCF_BV_ZERO_EXTEND
#define BCF_BV_ZERO_EXTEND(width, ext_width, arg)         \
	((struct bcf_expr_unary){                         \
		.code = BCF_BV | BCF_ZERO_EXTEND,         \
		.vlen = 1,                                \
		.params = (((ext_width) << 8) | (width)), \
		.arg0 = (arg),                            \
	})
#endif

#ifndef BCF_BV_SIGN_EXTEND
#define BCF_BV_SIGN_EXTEND(width, ext_width, arg)         \
	((struct bcf_expr_unary){                         \
		.code = BCF_BV | BCF_SIGN_EXTEND,         \
		.vlen = 1,                                \
		.params = (((ext_width) << 8) | (width)), \
		.arg0 = (arg),                            \
	})
#endif

#ifndef BCF_BV_XOR
#define BCF_BV_XOR(n, width, ...)         \
	((struct bcf_expr){               \
		.code = BCF_BV | BCF_XOR, \
		.vlen = (n),              \
		.params = (width),        \
		.args = { __VA_ARGS__ },  \
	})
#endif

#ifndef BCF_BOOL_XOR
#define BCF_BOOL_XOR(n, ...)                \
	((struct bcf_expr){                 \
		.code = BCF_BOOL | BCF_XOR, \
		.vlen = (n),                \
		.params = 0,                \
		.args = { __VA_ARGS__ },    \
	})
#endif

extern int check_exprs(void *st, bpfptr_t bcf_buf, u32 expr_size);

/* Test framework for BCF expression reference counting */
struct bcf_checker_state_test {
	struct bcf_expr *exprs;
	unsigned long *valid_idx;
	u32 expr_size;
	u32 id_gen;
	struct xarray expr_id_map;
};

struct bcf_expr_ref_test {
	union {
		struct {
			refcount_t refcnt;
			u32 id;
		};
		struct bcf_expr_ref_test *free_next;
	};
	int *freed_flag;
	struct bcf_expr expr;
};

static struct bcf_expr_ref_test *
alloc_expr_test(struct bcf_checker_state_test *st, u8 arg_n, int *freed_flag)
{
	struct bcf_expr_ref_test *eref;
	void *entry;
	size_t sz = sizeof(*eref) + sizeof(u32) * arg_n;

	eref = calloc(1, sz);
	if (!eref)
		return NULL;

	eref->id = st->id_gen++;
	eref->expr.vlen = arg_n;
	eref->freed_flag = freed_flag;

	entry = xa_store(&st->expr_id_map, eref->id, eref, GFP_KERNEL);
	if (xa_is_err(entry)) {
		free(eref);
		return NULL;
	}

	refcount_set(&eref->refcnt, 1);
	return eref;
}

static struct bcf_expr_ref_test *__to_ref_test(struct bcf_expr *expr)
{
	return container_of(expr, struct bcf_expr_ref_test, expr);
}

static bool is_static_expr_test(struct bcf_checker_state_test *st,
				struct bcf_expr *expr)
{
	(void)st;
	(void)expr;
	return false;
}

static bool is_static_expr_id_test(struct bcf_checker_state_test *st, u32 id)
{
	return id < st->expr_size;
}

static struct bcf_expr_ref_test *to_ref_test(struct bcf_checker_state_test *st,
					     struct bcf_expr *expr)
{
	return is_static_expr_test(st, expr) ? NULL : __to_ref_test(expr);
}

static struct bcf_expr_ref_test *
id_to_ref_test(struct bcf_checker_state_test *st, u32 id)
{
	return is_static_expr_id_test(st, id) ? NULL :
						xa_load(&st->expr_id_map, id);
}

static void free_expr_test(struct bcf_checker_state_test *st,
			   struct bcf_expr_ref_test *eref)
{
	if (eref->freed_flag)
		*eref->freed_flag = 1;
	free(eref);
}

static void push_free_test(struct bcf_checker_state_test *st,
			   struct bcf_expr_ref_test **head,
			   struct bcf_expr_ref_test *eref)
{
	if (eref && refcount_dec_and_test(&eref->refcnt)) {
		xa_erase(&st->expr_id_map, eref->id);
		eref->free_next = *head;
		*head = eref;
	}
}

static struct bcf_expr_ref_test *pop_free_test(struct bcf_expr_ref_test **head)
{
	struct bcf_expr_ref_test *eref = *head;

	if (eref)
		*head = eref->free_next;
	return eref;
}

#define bcf_for_each_arg_test(arg_id, expr)                              \
	for (u32 ___i = 0, arg_id;                                       \
	     ___i < (expr)->vlen && (arg_id = (expr)->args[___i], true); \
	     ___i++)

static void expr_put_test(struct bcf_checker_state_test *st,
			  struct bcf_expr *expr)
{
	struct bcf_expr_ref_test *free_head = NULL;

	push_free_test(st, &free_head, to_ref_test(st, expr));

	while (free_head) {
		struct bcf_expr_ref_test *eref = pop_free_test(&free_head);

		bcf_for_each_arg_test(arg_id, &eref->expr) push_free_test(
			st, &free_head, id_to_ref_test(st, arg_id));

		free_expr_test(st, eref);
	}
}

/* Test single dynamic expression */
static void test_expr_put_single(void)
{
	struct bcf_checker_state_test st = { 0 };
	int freed = 0;
	struct bcf_expr_ref_test *eref;

	xa_init(&st.expr_id_map);
	eref = alloc_expr_test(&st, 0, &freed);
	EXPECT_TRUE(eref != NULL);

	expr_put_test(&st, &eref->expr);
	EXPECT_EQ(freed, 1);

	xa_destroy(&st.expr_id_map);
}

/* Test dynamic expression with dynamic children */
static void test_expr_put_dynamic_children(void)
{
	struct bcf_checker_state_test st = { 0 };
	int freed_parent = 0, freed_child1 = 0, freed_child2 = 0;
	struct bcf_expr_ref_test *child1, *child2, *parent;

	xa_init(&st.expr_id_map);

	child1 = alloc_expr_test(&st, 0, &freed_child1);
	child2 = alloc_expr_test(&st, 0, &freed_child2);
	parent = alloc_expr_test(&st, 2, &freed_parent);
	parent->expr.args[0] = child1->id;
	parent->expr.args[1] = child2->id;

	expr_put_test(&st, &parent->expr);

	EXPECT_EQ(freed_parent, 1);
	EXPECT_EQ(freed_child1, 1);
	EXPECT_EQ(freed_child2, 1);

	xa_destroy(&st.expr_id_map);
}

/* Test reference counting */
static void test_expr_put_refcount(void)
{
	struct bcf_checker_state_test st = { 0 };
	int freed = 0;
	struct bcf_expr_ref_test *eref;

	xa_init(&st.expr_id_map);
	eref = alloc_expr_test(&st, 0, &freed);
	refcount_inc(&eref->refcnt); /* refcnt = 2 */

	expr_put_test(&st, &eref->expr);
	EXPECT_EQ(freed, 0); /* not freed yet */

	expr_put_test(&st, &eref->expr);
	EXPECT_EQ(freed, 1); /* now freed */

	xa_destroy(&st.expr_id_map);
}

/* Test DAG with shared child */
static void test_expr_put_dag(void)
{
	struct bcf_checker_state_test st = { 0 };
	int freed_parent1 = 0, freed_parent2 = 0, freed_shared = 0;
	struct bcf_expr_ref_test *shared, *parent1, *parent2;

	xa_init(&st.expr_id_map);

	shared = alloc_expr_test(&st, 0, &freed_shared);
	refcount_inc(&shared->refcnt); /* shared by two parents */

	parent1 = alloc_expr_test(&st, 1, &freed_parent1);
	parent2 = alloc_expr_test(&st, 1, &freed_parent2);
	parent1->expr.args[0] = shared->id;
	parent2->expr.args[0] = shared->id;

	expr_put_test(&st, &parent1->expr);
	EXPECT_EQ(freed_parent1, 1);
	EXPECT_EQ(freed_shared, 0); /* still held by parent2 */

	EXPECT_EQ(refcount_read(&shared->refcnt), 1);
	expr_put_test(&st, &parent2->expr);
	EXPECT_EQ(freed_parent2, 1);
	EXPECT_EQ(freed_shared, 1); /* now freed */

	xa_destroy(&st.expr_id_map);
}

/* Test complex DAG with multiple shared nodes */
static void test_expr_put_complex_dag(void)
{
	struct bcf_checker_state_test st = { 0 };
	int freed_a = 0, freed_b = 0, freed_c = 0, freed_d = 0, freed_e = 0;
	struct bcf_expr_ref_test *a, *b, *c, *d, *e;

	xa_init(&st.expr_id_map);

	/* Create DAG: A -> B, A -> C, B -> D, C -> D, D -> E */
	e = alloc_expr_test(&st, 0, &freed_e);

	d = alloc_expr_test(&st, 1, &freed_d);
	refcount_inc(&d->refcnt); /* B and C will reference D */
	d->expr.args[0] = e->id;

	c = alloc_expr_test(&st, 1, &freed_c);
	c->expr.args[0] = d->id;

	b = alloc_expr_test(&st, 1, &freed_b);
	b->expr.args[0] = d->id;

	a = alloc_expr_test(&st, 2, &freed_a);
	a->expr.args[0] = b->id;
	a->expr.args[1] = c->id;

	expr_put_test(&st, &a->expr);

	EXPECT_EQ(freed_a, 1);
	EXPECT_EQ(freed_b, 1);
	EXPECT_EQ(freed_c, 1);
	EXPECT_EQ(freed_d, 1);
	EXPECT_EQ(freed_e, 1);

	xa_destroy(&st.expr_id_map);
}

/* Test deep nested structure */
static void test_expr_put_deep_nested(void)
{
	struct bcf_checker_state_test st = { 0 };
	int freed_levels[10] = { 0 };
	struct bcf_expr_ref_test *nodes[10];
	int i;

	xa_init(&st.expr_id_map);

	/* Create a chain: 0 -> 1 -> 2 -> ... -> 9 */
	for (i = 0; i < 10; i++) {
		nodes[i] =
			alloc_expr_test(&st, i == 9 ? 0 : 1, &freed_levels[i]);
		if (i > 0)
			nodes[i - 1]->expr.args[0] = nodes[i]->id;
	}

	expr_put_test(&st, &nodes[0]->expr);

	for (i = 0; i < 10; i++)
		EXPECT_EQ(freed_levels[i], 1);

	xa_destroy(&st.expr_id_map);
}

/* Test multiple roots with shared subtrees */
static void test_expr_put_multiple_roots(void)
{
	struct bcf_checker_state_test st = { 0 };
	int freed_shared = 0, freed_root1 = 0, freed_root2 = 0, freed_root3 = 0;
	struct bcf_expr_ref_test *shared, *root1, *root2, *root3;

	xa_init(&st.expr_id_map);

	shared = alloc_expr_test(&st, 0, &freed_shared);
	refcount_inc(&shared->refcnt); /* root2 will reference */
	refcount_inc(&shared->refcnt); /* root3 will reference */

	root1 = alloc_expr_test(&st, 1, &freed_root1);
	root2 = alloc_expr_test(&st, 1, &freed_root2);
	root3 = alloc_expr_test(&st, 1, &freed_root3);

	root1->expr.args[0] = shared->id;
	root2->expr.args[0] = shared->id;
	root3->expr.args[0] = shared->id;

	expr_put_test(&st, &root1->expr);
	EXPECT_EQ(freed_root1, 1);
	EXPECT_EQ(freed_shared, 0); /* still held by root2 and root3 */

	expr_put_test(&st, &root2->expr);
	EXPECT_EQ(freed_root2, 1);
	EXPECT_EQ(freed_shared, 0); /* still held by root3 */

	expr_put_test(&st, &root3->expr);
	EXPECT_EQ(freed_root3, 1);
	EXPECT_EQ(freed_shared, 1); /* now freed */

	xa_destroy(&st.expr_id_map);
}

/* Test tree with multiple children per node */
static void test_expr_put_tree_structure(void)
{
	struct bcf_checker_state_test st = { 0 };
	int freed_nodes[7] = { 0 };
	struct bcf_expr_ref_test *nodes[7];
	int i;

	xa_init(&st.expr_id_map);

	/*
	 * Create a tree:
	 *       0
	 *      /|\
	 *     1 2 3
	 *    /| | |
	 *   4 5 6 6 (6 is shared)
	 */
	for (i = 0; i < 7; i++) {
		int arg_count = (i == 0)	   ? 3 :
				(i == 1)	   ? 2 :
				(i == 2 || i == 3) ? 1 :
						     0;
		nodes[i] = alloc_expr_test(&st, arg_count, &freed_nodes[i]);
	}

	nodes[0]->expr.args[0] = nodes[1]->id;
	nodes[0]->expr.args[1] = nodes[2]->id;
	nodes[0]->expr.args[2] = nodes[3]->id;

	nodes[1]->expr.args[0] = nodes[4]->id;
	nodes[1]->expr.args[1] = nodes[5]->id;

	nodes[2]->expr.args[0] = nodes[6]->id;
	nodes[3]->expr.args[0] = nodes[6]->id; /* shared */
	refcount_inc(&nodes[6]->refcnt);

	expr_put_test(&st, &nodes[0]->expr);

	for (i = 0; i < 7; i++)
		EXPECT_EQ(freed_nodes[i], 1);

	xa_destroy(&st.expr_id_map);
}

/* Test mixed static and dynamic expressions */
static void test_expr_put_mixed_static_dynamic(void)
{
	struct bcf_checker_state_test st = { 0 };
	struct bcf_expr static_exprs[3] = { 0 };
	int freed_dynamic = 0;
	struct bcf_expr_ref_test *dynamic;

	xa_init(&st.expr_id_map);
	st.exprs = static_exprs;
	st.expr_size = 3;

	dynamic = alloc_expr_test(&st, 3, &freed_dynamic);
	dynamic->expr.args[0] = 0; /* static */
	dynamic->expr.args[1] = 1; /* static */
	dynamic->expr.args[2] = 2; /* static */

	expr_put_test(&st, &dynamic->expr);
	EXPECT_EQ(freed_dynamic, 1);

	xa_destroy(&st.expr_id_map);
}

/* Test large number of references */
static void test_expr_put_many_references(void)
{
	struct bcf_checker_state_test st = { 0 };
	int freed_refs[100] = { 0 };
	struct bcf_expr_ref_test *refs[100];
	struct bcf_expr_ref_test *parent;
	int i;

	xa_init(&st.expr_id_map);

	for (i = 0; i < 100; i++)
		refs[i] = alloc_expr_test(&st, 0, &freed_refs[i]);

	parent = alloc_expr_test(&st, 100, NULL);
	for (i = 0; i < 100; i++)
		parent->expr.args[i] = refs[i]->id;

	expr_put_test(&st, &parent->expr);

	for (i = 0; i < 100; i++)
		EXPECT_EQ(freed_refs[i], 1);

	xa_destroy(&st.expr_id_map);
}

/* Test reference counting edge cases */
static void test_expr_put_refcount_edge_cases(void)
{
	struct bcf_checker_state_test st = { 0 };
	int freed = 0;
	struct bcf_expr_ref_test *eref;

	xa_init(&st.expr_id_map);
	eref = alloc_expr_test(&st, 0, &freed);

	/* Test multiple increments */
	refcount_inc(&eref->refcnt); /* refcnt = 2 */
	refcount_inc(&eref->refcnt); /* refcnt = 3 */
	refcount_inc(&eref->refcnt); /* refcnt = 4 */

	expr_put_test(&st, &eref->expr); /* refcnt = 3 */
	EXPECT_EQ(freed, 0);
	expr_put_test(&st, &eref->expr); /* refcnt = 2 */
	EXPECT_EQ(freed, 0);
	expr_put_test(&st, &eref->expr); /* refcnt = 1 */
	EXPECT_EQ(freed, 0);
	expr_put_test(&st, &eref->expr); /* refcnt = 0, should free */
	EXPECT_EQ(freed, 1);

	xa_destroy(&st.expr_id_map);
}

static struct test_case expr_put_tests[] = {
	TEST_ENTRY(test_expr_put_single),
	TEST_ENTRY(test_expr_put_dynamic_children),
	TEST_ENTRY(test_expr_put_refcount),
	TEST_ENTRY(test_expr_put_dag),
	TEST_ENTRY(test_expr_put_complex_dag),
	TEST_ENTRY(test_expr_put_deep_nested),
	TEST_ENTRY(test_expr_put_multiple_roots),
	TEST_ENTRY(test_expr_put_tree_structure),
	TEST_ENTRY(test_expr_put_mixed_static_dynamic),
	TEST_ENTRY(test_expr_put_many_references),
	TEST_ENTRY(test_expr_put_refcount_edge_cases),
};

// Helper: Write a bcf_expr (with vlen args) to a buffer at offset, return new offset
static size_t write_expr(void *buf, size_t offset, u8 code, u8 vlen, int params,
			 ...)
{
	struct bcf_expr *expr = (struct bcf_expr *)((char *)buf + offset);
	va_list ap;
	expr->code = code;
	expr->vlen = vlen;
	expr->params = params;
	va_start(ap, params);
	for (u8 i = 0; i < vlen; ++i)
		expr->args[i] = va_arg(ap, u32);
	va_end(ap);
	return offset + sizeof(struct bcf_expr) + vlen * sizeof(u32);
}

/* For expr equivalence comparison, see __expr_equiv(). */
#define BCF_MAX_CMP_STACK 128
struct bcf_cmp_stack_elem {
	struct bcf_expr *e0, *e1;
	u32 cur_arg;
};

#define __MAX_BCF_STACK (sizeof(struct bcf_cmp_stack_elem) * BCF_MAX_CMP_STACK)

/* For constant evaluation, see eval_const_expr(). */
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

struct bcf_rw_parse_state {
	const struct bcf_expr_nullary *rw_expr;
	u32 expr_id;
	u32 cur_arg;
	u32 size;
};

struct bcf_step_state {
	/* The conclusion of the current step. */
	struct bcf_expr *fact;
	u32 fact_id;
	/* The last step referring to the current step. After `last_ref`, the
	 * `fact` is no longer used by any other steps and can be freed.
	 */
	u32 last_ref;
};

// clang-format off
struct bcf_checker_state {
	/* Exprs from the proof, referred to as `static expr`. They exist
	 * during the entire checking phase.
	 */
	struct bcf_expr *exprs;
	/* Each expr of `exprs` is followed by their arguments. The `valid_idx`
	 * bitmap records the valid indices of exprs.
	 */
	unsigned long *valid_idx;
	u32 expr_size; /* size of exprs array. */
	/* For exprs that are allocated dynamically during proof checking, e.g.,
	 * conclusions from proof steps, they are refcounted, and each allocated
	 * expr has an id (increased after `expr_size`) and is stored in xarray.
	 *
	 * With this xarray, any routines below can exit early on any error
	 * without worrying about freeing the exprs allocated; they can be
	 * freed once when freeing the xarray, i.e., a lightweight gc.
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

// clang-format on

struct bcf_eval_result {
	u64 bv_res;
	bool bool_res;
	bool overflow;
};
extern int eval_const_expr(void *st, u32 expr_id, struct bcf_eval_result *res);
extern struct bcf_expr *id_to_expr(void *st, u32 id);
extern void free_checker_state(struct bcf_checker_state *st);
extern bool is_bv_val(u8 code);

static u32 emit_expr(const void *src, size_t sz, struct bcf_expr *buf, u32 *off)
{
	u32 off_ = *off;

	memcpy(&buf[*off], src, sz);
	*off += sz / sizeof(struct bcf_expr);
	return off_;
}

static u32 emit_variadic_expr(u8 code, u8 vlen, u16 params,
			      struct bcf_expr *buf, u32 *off, ...)
{
	struct bcf_expr e = { code, vlen, params };
	u32 off_ = *off;

	emit_expr(&e, sizeof(e), buf, off);

	va_list args;
	va_start(args, off);

	for (u32 i = 0; i < vlen; i++) {
		u32 id = va_arg(args, u32);
		emit_expr(&id, sizeof(id), buf, off);
	}

	va_end(args);

	return off_;
}

#define emit(e) emit_expr(&(e), sizeof(e), emit_buf, &emit_off)

static void run_check_exprs_test(void *buf, size_t buf_sz, int expected)
{
	struct bcf_checker_state *st =
		kzalloc(sizeof(struct bcf_checker_state), GFP_KERNEL);
	bpfptr_t bptr = make_bpfptr((uintptr_t)buf, 1);
	int err;

	xa_init(&st->expr_id_map);
	err = check_exprs(st, bptr, buf_sz / sizeof(struct bcf_expr));
	EXPECT_EQ(err, expected);
	free_checker_state(st);
}

#define MAX_EMIT_EXPR 128
#define CHECK_EXPRS_EXPECT(emit_block, expected)                      \
	do {                                                          \
		struct bcf_expr emit_buf[MAX_EMIT_EXPR] = { 0 };      \
		u32 emit_off = 0;                                     \
		emit_block run_check_exprs_test(                      \
			emit_buf, emit_off * sizeof(struct bcf_expr), \
			expected);                                    \
	} while (0)

static void test_check_exprs_valid_bv_var(void)
{
	CHECK_EXPRS_EXPECT(u32 idx = emit(BCF_BV_VAR32);, 0);
}

static void test_check_exprs_valid_bv_val(void)
{
	CHECK_EXPRS_EXPECT(u32 idx = emit(BCF_BV_VAL32(0x1234));, 0);
}

static void test_check_exprs_valid_bool_var(void)
{
	CHECK_EXPRS_EXPECT(u32 idx = emit(BCF_BOOL_VAR);, 0);
}

static void test_check_exprs_valid_bool_val(void)
{
	CHECK_EXPRS_EXPECT(u32 t = emit(BCF_BOOL_TRUE);
			   u32 f = emit(BCF_BOOL_FALSE);, 0);
}

static void test_check_exprs_valid_bv_binop(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 v1 = emit(BCF_BV_VAR32);
			   u32 add = emit(BCF_BV_BINOP(BPF_ADD, 32, v0, v1));
			   , 0);
}

static void test_check_exprs_invalid_arg_index(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 bad = emit(BCF_BV_BINOP(BPF_ADD, 32, v0,
						       2)); // 2 is invalid
			   , -EINVAL);
}

static void test_check_exprs_invalid_future_ref(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 bad = emit(BCF_BV_BINOP(BPF_ADD, 32, 1,
						       0)); // 1 is future/self
			   , -EINVAL);
}

static void test_check_exprs_invalid_opcode(void)
{
	CHECK_EXPRS_EXPECT(u32 bad = emit(((struct bcf_expr){
				   .code = 0xff, .vlen = 0, .params = 0 }));
			   , -EINVAL);
}

static void test_check_exprs_invalid_arity(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 bad = emit_variadic_expr(BCF_BV | BPF_ADD, 1, 32,
							emit_buf, &emit_off,
							v0);
			   , -EINVAL);
}

static void test_check_exprs_invalid_type(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 b0 = emit(BCF_BOOL_VAR);
			   u32 bad = emit(BCF_BV_BINOP(BPF_ADD, 32, v0, b0));
			   , -EINVAL);
}

static void test_check_exprs_bv_size(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 bad = emit_variadic_expr(BCF_BV | BCF_BVSIZE, 1,
							24, emit_buf, &emit_off,
							v0);
			   , 0);
}

static void test_check_exprs_invalid_list_elem_type(void)
{
	CHECK_EXPRS_EXPECT(u32 b0 = emit(BCF_BOOL_VAR);
			   u32 bad = emit_variadic_expr(
				   BCF_LIST | BCF_VAL, 1, (BCF_BV << 8) | 32,
				   emit_buf, &emit_off, b0);
			   , -EINVAL);
}

// --- BV Operator Tests ---

// Helper: Add two valid BV vars and return offset after them
static size_t add_two_bv_vars(char *buf, size_t off, u16 width)
{
	off = write_expr(buf, off, BCF_BV | BCF_VAR, 0, width); // 0
	off = write_expr(buf, off, BCF_BV | BCF_VAR, 0, width); // 1
	return off;
}

static void test_check_exprs_bv_add_success(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 v1 = emit(BCF_BV_VAR32);
			   u32 add = emit(BCF_BV_BINOP(BPF_ADD, 32, v0, v1));
			   , 0);
}
static void test_check_exprs_bv_add_fail_arity(void)
{
	CHECK_EXPRS_EXPECT(
		u32 v0 = emit(BCF_BV_VAR32); u32 v1 = emit(BCF_BV_VAR32);
		u32 bad = emit_variadic_expr(BCF_BV | BPF_ADD, 1, 32, emit_buf,
					     &emit_off, v0);
		, -EINVAL);
}
static void test_check_exprs_bv_add_fail_type(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 b0 = emit(BCF_BOOL_VAR);
			   u32 bad = emit(BCF_BV_BINOP(BPF_ADD, 32, v0, b0));
			   , -EINVAL);
}

static void test_check_exprs_bv_sub_success(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 v1 = emit(BCF_BV_VAR32);
			   u32 sub = emit(BCF_BV_BINOP(BPF_SUB, 32, v0, v1));
			   , 0);
}
static void test_check_exprs_bv_sub_fail_arity(void)
{
	CHECK_EXPRS_EXPECT(
		u32 v0 = emit(BCF_BV_VAR32); u32 v1 = emit(BCF_BV_VAR32);
		u32 bad = emit_variadic_expr(BCF_BV | BPF_SUB, 3, 32, emit_buf,
					     &emit_off, v0, v1, v1);
		, -EINVAL);
}

static void test_check_exprs_bv_mul_success(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 v1 = emit(BCF_BV_VAR32);
			   u32 mul = emit(BCF_BV_BINOP(BPF_MUL, 32, v0, v1));
			   , 0);
}
static void test_check_exprs_bv_mul_fail_type(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 b0 = emit(BCF_BOOL_VAR);
			   u32 bad = emit(BCF_BV_BINOP(BPF_MUL, 32, v0, b0));
			   , -EINVAL);
}

static void test_check_exprs_bv_div_success(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 v1 = emit(BCF_BV_VAR32);
			   u32 div = emit(BCF_BV_BINOP(BPF_DIV, 32, v0, v1));
			   , 0);
}
static void test_check_exprs_bv_div_fail_arity(void)
{
	CHECK_EXPRS_EXPECT(
		u32 v0 = emit(BCF_BV_VAR32); u32 v1 = emit(BCF_BV_VAR32);
		u32 bad = emit_variadic_expr(BCF_BV | BPF_DIV, 1, 32, emit_buf,
					     &emit_off, v0);
		, -EINVAL);
}

static void test_check_exprs_bv_or_success(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 v1 = emit(BCF_BV_VAR32);
			   u32 or = emit(BCF_BV_BINOP(BPF_OR, 32, v0, v1));, 0);
}
static void test_check_exprs_bv_or_fail_type(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 b0 = emit(BCF_BOOL_VAR);
			   u32 bad = emit(BCF_BV_BINOP(BPF_OR, 32, v0, b0));
			   , -EINVAL);
}

static void test_check_exprs_bv_and_success(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 v1 = emit(BCF_BV_VAR32);
			   u32 and = emit(BCF_BV_BINOP(BPF_AND, 32, v0, v1));
			   , 0);
}
static void test_check_exprs_bv_and_fail_arity(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 v1 = emit(BCF_BV_VAR32);
			   u32 bad = emit_variadic_expr(BCF_BV | BPF_AND, 0, 32,
							emit_buf, &emit_off);
			   , -EINVAL);
}

static void test_check_exprs_bv_lsh_success(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 v1 = emit(BCF_BV_VAR32);
			   u32 lsh = emit(BCF_BV_BINOP(BPF_LSH, 32, v0, v1));
			   , 0);
}
static void test_check_exprs_bv_lsh_fail_type(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 b0 = emit(BCF_BOOL_VAR);
			   u32 bad = emit(BCF_BV_BINOP(BPF_LSH, 32, v0, b0));
			   , -EINVAL);
}

static void test_check_exprs_bv_rsh_success(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 v1 = emit(BCF_BV_VAR32);
			   u32 rsh = emit(BCF_BV_BINOP(BPF_RSH, 32, v0, v1));
			   , 0);
}
static void test_check_exprs_bv_rsh_fail_arity(void)
{
	CHECK_EXPRS_EXPECT(
		u32 v0 = emit(BCF_BV_VAR32); u32 v1 = emit(BCF_BV_VAR32);
		u32 bad = emit_variadic_expr(BCF_BV | BPF_RSH, 3, 32, emit_buf,
					     &emit_off, v0, v1, v1);
		, -EINVAL);
}

static void test_check_exprs_bv_neg_success(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 neg = emit_variadic_expr(BCF_BV | BPF_NEG, 1, 32,
							emit_buf, &emit_off,
							v0);
			   , 0);
}
static void test_check_exprs_bv_neg_fail_arity(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 bad = emit_variadic_expr(BCF_BV | BPF_NEG, 0, 32,
							emit_buf, &emit_off);
			   , -EINVAL);
}

static void test_check_exprs_bv_mod_success(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 v1 = emit(BCF_BV_VAR32);
			   u32 mod = emit(BCF_BV_BINOP(BPF_MOD, 32, v0, v1));
			   , 0);
}

static void test_check_exprs_bv_mod_fail_type(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 b0 = emit(BCF_BOOL_VAR);
			   u32 bad = emit(BCF_BV_BINOP(BPF_MOD, 32, v0, b0));
			   , -EINVAL);
}

static void test_check_exprs_bv_xor_success(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 v1 = emit(BCF_BV_VAR32);
			   u32 xor = emit(BCF_BV_BINOP(BPF_XOR, 32, v0, v1));
			   , 0);
}
static void test_check_exprs_bv_xor_fail_arity(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 v1 = emit(BCF_BV_VAR32);
			   u32 bad = emit_variadic_expr(BCF_BV | BPF_XOR, 0, 32,
							emit_buf, &emit_off);
			   , -EINVAL);
}

static void test_check_exprs_bv_arsh_success(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 v1 = emit(BCF_BV_VAR32);
			   u32 arsh = emit(BCF_BV_BINOP(BPF_ARSH, 32, v0, v1));
			   , 0);
}

static void test_check_exprs_bv_arsh_fail_type(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 b0 = emit(BCF_BOOL_VAR);
			   u32 bad = emit(BCF_BV_BINOP(BPF_ARSH, 32, v0, b0));
			   , -EINVAL);
}

static struct test_case check_exprs_tests[] = {
	TEST_ENTRY(test_check_exprs_valid_bv_var),
	TEST_ENTRY(test_check_exprs_valid_bv_val),
	TEST_ENTRY(test_check_exprs_valid_bool_var),
	TEST_ENTRY(test_check_exprs_valid_bool_val),
	TEST_ENTRY(test_check_exprs_valid_bv_binop),
	TEST_ENTRY(test_check_exprs_invalid_arg_index),
	TEST_ENTRY(test_check_exprs_invalid_future_ref),
	TEST_ENTRY(test_check_exprs_invalid_opcode),
	TEST_ENTRY(test_check_exprs_invalid_arity),
	TEST_ENTRY(test_check_exprs_invalid_type),
	TEST_ENTRY(test_check_exprs_bv_size),
	TEST_ENTRY(test_check_exprs_invalid_list_elem_type),
	TEST_ENTRY(test_check_exprs_bv_add_success),
	TEST_ENTRY(test_check_exprs_bv_add_fail_arity),
	TEST_ENTRY(test_check_exprs_bv_add_fail_type),
	TEST_ENTRY(test_check_exprs_bv_sub_success),
	TEST_ENTRY(test_check_exprs_bv_sub_fail_arity),
	TEST_ENTRY(test_check_exprs_bv_mul_success),
	TEST_ENTRY(test_check_exprs_bv_mul_fail_type),
	TEST_ENTRY(test_check_exprs_bv_div_success),
	TEST_ENTRY(test_check_exprs_bv_div_fail_arity),
	TEST_ENTRY(test_check_exprs_bv_or_success),
	TEST_ENTRY(test_check_exprs_bv_or_fail_type),
	TEST_ENTRY(test_check_exprs_bv_and_success),
	TEST_ENTRY(test_check_exprs_bv_and_fail_arity),
	TEST_ENTRY(test_check_exprs_bv_lsh_success),
	TEST_ENTRY(test_check_exprs_bv_lsh_fail_type),
	TEST_ENTRY(test_check_exprs_bv_rsh_success),
	TEST_ENTRY(test_check_exprs_bv_rsh_fail_arity),
	TEST_ENTRY(test_check_exprs_bv_neg_success),
	TEST_ENTRY(test_check_exprs_bv_neg_fail_arity),
	TEST_ENTRY(test_check_exprs_bv_mod_success),
	TEST_ENTRY(test_check_exprs_bv_mod_fail_type),
	TEST_ENTRY(test_check_exprs_bv_xor_success),
	TEST_ENTRY(test_check_exprs_bv_xor_fail_arity),
	TEST_ENTRY(test_check_exprs_bv_arsh_success),
	TEST_ENTRY(test_check_exprs_bv_arsh_fail_type),
};

extern int expr_equiv(struct bcf_checker_state *st, struct bcf_expr *e0,
		      struct bcf_expr *e1);

#define EXPR_EQUIV_EXPECT(emit_block, idx0, idx1, expected)                \
	do {                                                               \
		struct bcf_expr emit_buf[MAX_EMIT_EXPR] = { 0 };           \
		u32 emit_off = 0;                                          \
		emit_block struct bcf_checker_state st = { 0 };            \
		st.exprs = emit_buf;                                       \
		st.expr_size = emit_off;                                   \
		st.id_gen = emit_off;                                      \
		xa_init(&st.expr_id_map);                                  \
		int result =                                               \
			expr_equiv(&st, &emit_buf[idx0], &emit_buf[idx1]); \
		EXPECT_EQ(result, expected);                               \
		xa_destroy(&st.expr_id_map);                               \
	} while (0)

static void test_expr_equiv_simple_equal(void)
{
	EXPR_EQUIV_EXPECT(u32 idx0 = emit(BCF_BV_VAR32);
			  u32 idx1 = emit(BCF_BV_VAR32);, idx0, idx1, 0);
}

static void test_expr_equiv_simple_neq_code(void)
{
	EXPR_EQUIV_EXPECT(u32 idx0 = emit(BCF_BV_VAR32);
			  u32 idx1 = emit(BCF_BOOL_VAR);, idx0, idx1, 0);
}

static void test_expr_equiv_simple_neq_params(void)
{
	EXPR_EQUIV_EXPECT(u32 idx0 = emit(BCF_BV_VAR32);
			  u32 idx1 = emit(BCF_BV_VAR64);, idx0, idx1, 0);
}

static void test_expr_equiv_bv_val_equal(void)
{
	EXPR_EQUIV_EXPECT(u32 idx0 = emit(BCF_BV_VAL32(0x1234));
			  u32 idx1 = emit(BCF_BV_VAL32(0x1234));
			  , idx0, idx1, 1);
}

static void test_expr_equiv_bv_val_neq(void)
{
	EXPR_EQUIV_EXPECT(u32 idx0 = emit(BCF_BV_VAL32(0x1234));
			  u32 idx1 = emit(BCF_BV_VAL32(0x5678));
			  , idx0, idx1, 0);
}

static void test_expr_equiv_nested_equal(void)
{
	EXPR_EQUIV_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			  u32 v1 = emit(BCF_BV_VAR32);
			  u32 n0 = emit(BCF_BV_BINOP(BPF_NEG, 32, v0, v0));
			  u32 n1 = emit(BCF_BV_BINOP(BPF_NEG, 32, v1, v1));
			  , n0, n1, 0);
}

static void test_expr_equiv_nested_neq(void)
{
	EXPR_EQUIV_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			  u32 v1 = emit(BCF_BV_VAR64);
			  u32 n0 = emit(BCF_BV_BINOP(BPF_NEG, 32, v0, v0));
			  u32 n1 = emit(BCF_BV_BINOP(BPF_NEG, 32, v1, v1));
			  , n0, n1, 0);
}

static void test_expr_equiv_var_mapping(void)
{
	EXPR_EQUIV_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			  u32 v1 = emit(BCF_BV_VAR32);
			  u32 a0 = emit(BCF_ALU32(BPF_ADD, v0, v0));
			  u32 a1 = emit(BCF_ALU32(BPF_ADD, v1, v1));
			  , a0, a1, 0);
}

static void test_expr_equiv_var_mapping_neq(void)
{
	/* while the arg order is different, two exprs are syntactically
	 * equivalent.
	 */
	EXPR_EQUIV_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			  u32 v1 = emit(BCF_BV_VAR32);
			  u32 a0 = emit(BCF_ALU32(BPF_ADD, v0, v1));
			  u32 a1 = emit(BCF_ALU32(BPF_ADD, v1, v0));
			  , a0, a1, 0);
}

static void test_expr_equiv_self_pointer(void)
{
	EXPR_EQUIV_EXPECT(u32 idx0 = emit(BCF_BV_VAR32);, idx0, idx0, 1);
}

static void test_expr_equiv_bool_val_true_false(void)
{
	EXPR_EQUIV_EXPECT(u32 t = emit(BCF_BOOL_TRUE);
			  u32 f = emit(BCF_BOOL_FALSE);, t, f, 0);
}

static void test_expr_equiv_deeply_nested(void)
{
	EXPR_EQUIV_EXPECT(
		u32 v0 = emit(BCF_BV_VAR32); u32 v1 = emit(BCF_BV_VAR32);
		u32 add0 = emit(BCF_ALU32(BPF_ADD, v0, v1));
		u32 add1 = emit(BCF_ALU32(BPF_ADD, v0, v1));
		u32 neg0 = emit(BCF_BV_BINOP(BPF_NEG, 32, add0, add0));
		u32 neg1 = emit(BCF_BV_BINOP(BPF_NEG, 32, add1, add1));
		u32 xor0 = emit(BCF_BV_BINOP(BPF_XOR, 32, neg0, v1));
		u32 xor1 = emit(BCF_BV_BINOP(BPF_XOR, 32, neg1, v1));
		, xor0, xor1, 1);
}

static void test_expr_equiv_var_mapping_multi_level(void)
{
	EXPR_EQUIV_EXPECT(
		u32 a = emit(BCF_BV_VAR32); u32 b = emit(BCF_BV_VAR32);
		u32 c = emit(BCF_BV_VAR32);
		u32 ab = emit(BCF_ALU32(BPF_ADD, a, b));
		u32 abc = emit(BCF_ALU32(BPF_ADD, ab, c));
		u32 x = emit(BCF_BV_VAR32); u32 y = emit(BCF_BV_VAR32);
		u32 z = emit(BCF_BV_VAR32);
		u32 xy = emit(BCF_ALU32(BPF_ADD, x, y));
		u32 xyz = emit(BCF_ALU32(BPF_ADD, xy, z));, abc, xyz, 0);
}

static void test_expr_equiv_ite_and_list(void)
{
	// ITE(cond, a, b) vs ITE(cond, a, b)
	EXPR_EQUIV_EXPECT(u32 cond = emit(BCF_BOOL_VAR);
			  u32 a = emit(BCF_BV_VAR32);
			  u32 b = emit(BCF_BV_VAR32);
			  u32 idx0 = emit(BCF_BV_ITE(32, cond, a, b));
			  u32 idx1 = emit(BCF_BV_ITE(32, cond, a, b));
			  , idx0, idx1, 1);
	EXPR_EQUIV_EXPECT(
		u32 a = emit(BCF_BV_VAR32); u32 b = emit(BCF_BV_VAR32);
		u32 list0 = emit_variadic_expr(BCF_LIST | BCF_VAL, 3, BCF_BV,
					       emit_buf, &emit_off, a, b, a);
		u32 list1 = emit_variadic_expr(BCF_LIST | BCF_VAL, 3, BCF_BV,
					       emit_buf, &emit_off, a, b, a);
		, list0, list1, 1);
	EXPR_EQUIV_EXPECT(
		u32 a = emit(BCF_BV_VAR32); u32 b = emit(BCF_BV_VAR32);
		u32 list2 = emit_variadic_expr(BCF_LIST | BCF_VAL, 3, BCF_BV,
					       emit_buf, &emit_off, a, b, a);
		u32 x = emit(BCF_BV_VAR32); u32 y = emit(BCF_BV_VAR32);
		u32 list3 = emit_variadic_expr(BCF_LIST | BCF_VAL, 3, BCF_BV,
					       emit_buf, &emit_off, x, y, x);
		, list2, list3, 0);
}

static void test_expr_equiv_conj_disj_vlen(void)
{
	// Conjunction with different vlen
	EXPR_EQUIV_EXPECT(
		u32 a = emit(BCF_BOOL_VAR); u32 b = emit(BCF_BOOL_VAR);
		u32 c = emit(BCF_BOOL_VAR);
		u32 conj2 = emit_variadic_expr(BCF_BOOL | BCF_CONJ, 2, 0,
					       emit_buf, &emit_off, a, b);
		u32 conj3 = emit_variadic_expr(BCF_BOOL | BCF_CONJ, 3, 0,
					       emit_buf, &emit_off, a, b, c);
		, conj2, conj3, 0);
	EXPR_EQUIV_EXPECT(
		u32 a = emit(BCF_BOOL_VAR); u32 b = emit(BCF_BOOL_VAR);
		u32 disj0 = emit_variadic_expr(BCF_BOOL | BCF_DISJ, 2, 0,
					       emit_buf, &emit_off, a, b);
		u32 x = emit(BCF_BOOL_VAR); u32 y = emit(BCF_BOOL_VAR);
		u32 disj1 = emit_variadic_expr(BCF_BOOL | BCF_DISJ, 2, 0,
					       emit_buf, &emit_off, x, y);
		, disj0, disj1, 0);

	EXPR_EQUIV_EXPECT(
		u32 a = emit(BCF_BOOL_VAR); u32 b = emit(BCF_BOOL_VAR);
		u32 disj0 = emit_variadic_expr(BCF_BOOL | BCF_DISJ, 2, 0,
					       emit_buf, &emit_off, a, b);
		u32 disj1 = emit_variadic_expr(BCF_BOOL | BCF_DISJ, 2, 0,
					       emit_buf, &emit_off, a, b);
		, disj0, disj1, 1);
}

static void test_expr_equiv_bbt_concat_extract(void)
{
	// BCF_FROM_BOOL: bit-blast of bools to bv
	EXPR_EQUIV_EXPECT(
		u32 b0 = emit(BCF_BOOL_VAR); u32 b1 = emit(BCF_BOOL_VAR);
		u32 bbt0 = emit_variadic_expr(BCF_BV | BCF_FROM_BOOL, 2, 32,
					      emit_buf, &emit_off, b0, b1);
		u32 x0 = emit(BCF_BOOL_VAR); u32 x1 = emit(BCF_BOOL_VAR);
		u32 bbt1 = emit_variadic_expr(BCF_BV | BCF_FROM_BOOL, 2, 32,
					      emit_buf, &emit_off, x0, x1);
		, bbt0, bbt1, 0);
	EXPR_EQUIV_EXPECT(
		u32 b0 = emit(BCF_BOOL_VAR); u32 b1 = emit(BCF_BOOL_VAR);
		u32 bbt0 = emit_variadic_expr(BCF_BV | BCF_FROM_BOOL, 2, 32,
					      emit_buf, &emit_off, b0, b1);
		u32 bbt1 = emit_variadic_expr(BCF_BV | BCF_FROM_BOOL, 2, 32,
					      emit_buf, &emit_off, b0, b1);
		, bbt0, bbt1, 1);
	// CONCAT: concat two bv vars
	EXPR_EQUIV_EXPECT(
		u32 v0 = emit(BCF_BV_VAR32); u32 v1 = emit(BCF_BV_VAR32);
		u32 concat0 = emit_variadic_expr(BCF_BV | BCF_CONCAT, 2, 64,
						 emit_buf, &emit_off, v0, v1);
		u32 x0 = emit(BCF_BV_VAR32); u32 x1 = emit(BCF_BV_VAR32);
		u32 concat1 = emit_variadic_expr(BCF_BV | BCF_CONCAT, 2, 64,
						 emit_buf, &emit_off, x0, x1);
		, concat0, concat1, 0);
	EXPR_EQUIV_EXPECT(
		u32 v0 = emit(BCF_BV_VAR32); u32 v1 = emit(BCF_BV_VAR32);
		u32 concat0 = emit_variadic_expr(BCF_BV | BCF_CONCAT, 2, 64,
						 emit_buf, &emit_off, v0, v1);
		u32 concat1 = emit_variadic_expr(BCF_BV | BCF_CONCAT, 2, 64,
						 emit_buf, &emit_off, v0, v1);
		, concat0, concat1, 1);
	// EXTRACT: extract bits from bv (use the correct macro signature)
	EXPR_EQUIV_EXPECT(u32 v = emit(BCF_BV_VAR32);
			  u32 ext0 = emit(BCF_BV_EXTRACT(16, v));
			  u32 ext1 = emit(BCF_BV_EXTRACT(16, v));
			  , ext0, ext1, 1);
}

static void test_expr_equiv_sign_zero_extend(void)
{
	// Zero extend
	EXPR_EQUIV_EXPECT(u32 v = emit(BCF_BV_VAR8);
			  u32 zext0 = emit(BCF_BV_ZERO_EXTEND(16, 8, v));
			  u32 zext1 = emit(BCF_BV_ZERO_EXTEND(16, 8, v));
			  , zext0, zext1, 1);
	// Sign extend
	EXPR_EQUIV_EXPECT(u32 v = emit(BCF_BV_VAR8);
			  u32 sext0 = emit(BCF_BV_SIGN_EXTEND(16, 8, v));
			  u32 x = emit(BCF_BV_VAR8);
			  u32 sext1 = emit(BCF_BV_SIGN_EXTEND(16, 8, x));
			  , sext0, sext1, 0);
}

static void test_expr_equiv_variadic_xor(void)
{
	// Variadic XOR (bv)
	EXPR_EQUIV_EXPECT(
		u32 v0 = emit(BCF_BV_VAR32); u32 v1 = emit(BCF_BV_VAR32);
		u32 v2 = emit(BCF_BV_VAR32);
		u32 xor0 = emit_variadic_expr(BCF_BV | BCF_XOR, 3, 32, emit_buf,
					      &emit_off, v0, v1, v2);
		u32 x0 = emit(BCF_BV_VAR32); u32 x1 = emit(BCF_BV_VAR32);
		u32 x2 = emit(BCF_BV_VAR32);
		u32 xor1 = emit_variadic_expr(BCF_BV | BCF_XOR, 3, 32, emit_buf,
					      &emit_off, x0, x1, x2);
		, xor0, xor1, 0);
	EXPR_EQUIV_EXPECT(
		u32 v0 = emit(BCF_BV_VAR32); u32 v1 = emit(BCF_BV_VAR32);
		u32 v2 = emit(BCF_BV_VAR32);
		u32 xor0 = emit_variadic_expr(BCF_BV | BCF_XOR, 3, 32, emit_buf,
					      &emit_off, v0, v1, v2);
		u32 xor1 = emit_variadic_expr(BCF_BV | BCF_XOR, 3, 32, emit_buf,
					      &emit_off, v0, v1, v2);
		, xor0, xor1, 1);
	// Variadic XOR (bool)
	EXPR_EQUIV_EXPECT(
		u32 b0 = emit(BCF_BOOL_VAR); u32 b1 = emit(BCF_BOOL_VAR);
		u32 b2 = emit(BCF_BOOL_VAR);
		u32 bxor0 = emit_variadic_expr(BCF_BOOL | BCF_XOR, 3, 0,
					       emit_buf, &emit_off, b0, b1, b2);
		u32 x0 = emit(BCF_BOOL_VAR); u32 x1 = emit(BCF_BOOL_VAR);
		u32 x2 = emit(BCF_BOOL_VAR);
		u32 bxor1 = emit_variadic_expr(BCF_BOOL | BCF_XOR, 3, 0,
					       emit_buf, &emit_off, x0, x1, x2);
		, bxor0, bxor1, 0);
}

/* -------------------------------------------------------------------- */
/* Constant evaluation tests                                           */
/* -------------------------------------------------------------------- */

static void test_eval_bool_nested(void)
{
	struct bcf_checker_state *st =
		kzalloc(sizeof(struct bcf_checker_state), GFP_KERNEL);

	/* prepare static expr array */
	st->expr_size = 16;
	st->exprs = calloc(st->expr_size, sizeof(struct bcf_expr));
	st->valid_idx = bitmap_zalloc(st->expr_size, GFP_KERNEL);
	xa_init(&st->expr_id_map);

	u32 id_true = 0; /* will allocate later */
	u32 id_false = 0;

	/* literals */
	struct bcf_expr e_true = { .code = BCF_BOOL | BCF_VAL,
				   .vlen = 0,
				   .params = BCF_TRUE };
	struct bcf_expr e_false = { .code = BCF_BOOL | BCF_VAL,
				    .vlen = 0,
				    .params = BCF_FALSE };
	id_true = st->id_gen;
	st->exprs[id_true] = e_true;
	__set_bit(id_true, st->valid_idx);
	st->id_gen++;
	id_false = st->id_gen;
	st->exprs[id_false] = e_false;
	__set_bit(id_false, st->valid_idx);
	st->id_gen++;
	st->true_expr = id_true;
	st->false_expr = id_false;

	/* or = (true OR false) */
	struct bcf_expr or_e = { .code = BCF_BOOL | BCF_DISJ, .vlen = 2 };
	u32 id_or = st->id_gen;
	st->exprs[id_or] = or_e;
	__set_bit(id_or, st->valid_idx);
	st->id_gen++;
	st->exprs[st->id_gen++] = *(struct bcf_expr *)(void *)&id_true;
	st->exprs[st->id_gen++] = *(struct bcf_expr *)(void *)&id_false;

	/* not false */
	struct bcf_expr not_e = { .code = BCF_BOOL | BCF_NOT, .vlen = 1 };
	u32 id_not = st->id_gen;
	st->exprs[id_not] = not_e;
	__set_bit(id_not, st->valid_idx);
	st->id_gen++;
	st->exprs[st->id_gen++] = *(struct bcf_expr *)(void *)&id_false;

	/* and (or, not) */
	struct bcf_expr and_e = { .code = BCF_BOOL | BCF_CONJ, .vlen = 2 };
	u32 id_and = st->id_gen;
	st->exprs[id_and] = and_e;
	__set_bit(id_and, st->valid_idx);
	st->id_gen++;
	st->exprs[st->id_gen++] = *(struct bcf_expr *)(void *)&id_or;
	st->exprs[st->id_gen++] = *(struct bcf_expr *)(void *)&id_not;

	struct bcf_eval_result res = { 0 };
	EXPECT_EQ(eval_const_expr(st, id_and, &res), 0);
	EXPECT_EQ(res.bool_res, true);

	free_checker_state(st);
}

static void test_eval_bv_add(void)
{
	struct bcf_checker_state *st =
		kzalloc(sizeof(struct bcf_checker_state), GFP_KERNEL);
	st->expr_size = 128;
	st->exprs = calloc(st->expr_size, sizeof(struct bcf_expr));
	st->valid_idx = bitmap_zalloc(st->expr_size, GFP_KERNEL);
	xa_init(&st->expr_id_map);

	/* true/false literals required by evaluator for builtins */
	struct bcf_expr t = { .code = BCF_BOOL | BCF_VAL,
			      .vlen = 0,
			      .params = BCF_TRUE };
	struct bcf_expr f = { .code = BCF_BOOL | BCF_VAL,
			      .vlen = 0,
			      .params = BCF_FALSE };
	st->exprs[0] = t;
	__set_bit(0, st->valid_idx);
	st->exprs[1] = f;
	__set_bit(1, st->valid_idx);
	st->true_expr = 0;
	st->false_expr = 1;
	st->id_gen = 2;

	/* bv literals 0x12 and 0x34 (8-bit) */
	struct bcf_expr lit12 = { .code = BCF_BV | BCF_VAL,
				  .vlen = 1,
				  .params = 8 };
	u32 id12 = st->id_gen++;
	st->exprs[id12] = lit12;
	__set_bit(id12, st->valid_idx);
	u32 val12 = 0x12;
	st->exprs[st->id_gen++] = *(struct bcf_expr *)(void *)&val12;

	struct bcf_expr lit34 = { .code = BCF_BV | BCF_VAL,
				  .vlen = 1,
				  .params = 8 };
	u32 id34 = st->id_gen++;
	st->exprs[id34] = lit34;
	__set_bit(id34, st->valid_idx);
	u32 val34 = 0x34;
	st->exprs[st->id_gen++] = *(struct bcf_expr *)(void *)&val34;
	/* add node */
	struct bcf_expr add_e = { .code = BCF_BV | BPF_ADD,
				  .vlen = 2,
				  .params = 8 };
	u32 id_add = st->id_gen++;
	st->exprs[id_add] = add_e;
	__set_bit(id_add, st->valid_idx);
	st->exprs[st->id_gen++] = *(struct bcf_expr *)(void *)&id12;
	st->exprs[st->id_gen++] = *(struct bcf_expr *)(void *)&id34;
	st->expr_size = st->id_gen;

	struct bcf_eval_result res = { 0 };
	int err = eval_const_expr(st, id_add, &res);
	EXPECT_EQ(err, 0);
	if (!err) {
		EXPECT_EQ(res.bv_res, (u32)0x46);
		EXPECT_EQ(res.overflow, false);
	}

	free_checker_state(st);
}

static struct test_case eval_tests[] = {
	TEST_ENTRY(test_eval_bool_nested),
	TEST_ENTRY(test_eval_bv_add),
};

static struct test_case expr_equiv_tests[] = {
	TEST_ENTRY(test_expr_equiv_simple_equal),
	TEST_ENTRY(test_expr_equiv_simple_neq_code),
	TEST_ENTRY(test_expr_equiv_simple_neq_params),
	TEST_ENTRY(test_expr_equiv_bv_val_equal),
	TEST_ENTRY(test_expr_equiv_bv_val_neq),
	TEST_ENTRY(test_expr_equiv_nested_equal),
	TEST_ENTRY(test_expr_equiv_nested_neq),
	TEST_ENTRY(test_expr_equiv_var_mapping),
	TEST_ENTRY(test_expr_equiv_var_mapping_neq),
	TEST_ENTRY(test_expr_equiv_self_pointer),
	TEST_ENTRY(test_expr_equiv_bool_val_true_false),
	TEST_ENTRY(test_expr_equiv_deeply_nested),
	TEST_ENTRY(test_expr_equiv_var_mapping_multi_level),
	TEST_ENTRY(test_expr_equiv_ite_and_list),
	TEST_ENTRY(test_expr_equiv_conj_disj_vlen),
	TEST_ENTRY(test_expr_equiv_bbt_concat_extract),
	TEST_ENTRY(test_expr_equiv_sign_zero_extend),
	TEST_ENTRY(test_expr_equiv_variadic_xor),
};

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
	struct bcf_expr expr;
};

extern int alloc_builtins(struct bcf_checker_state *st);
extern int apply_rewrite(struct bcf_checker_state *st,
			 struct bcf_expr_ref **fact, u32 rid, u32 *pm_steps,
			 u32 pm_step_n, u32 *args, u32 arg_n);
extern const struct bcf_rewrite *const bcf_rewrites[__MAX_BCF_REWRITES];

static u32 __append_word(struct bcf_checker_state *st, u32 word)
{
	u32 id = st->id_gen;
	st->exprs[st->id_gen++] = *(struct bcf_expr *)(void *)&word;
	return id;
}

static u32 emit_static_expr(struct bcf_checker_state *st, u32 cap,
			    struct bcf_expr *expr)
{
	u32 id = st->id_gen;
	EXPECT_TRUE(id + 1 <= cap);
	st->exprs[id] = *expr;
	__set_bit(id, st->valid_idx);
	st->id_gen++;
	EXPECT_TRUE(st->id_gen + expr->vlen <= cap);
	return id;
}

static u32 emit_bool_val(struct bcf_checker_state *st, u32 cap, bool v)
{
	struct bcf_expr e = { .code = BCF_BOOL | BCF_VAL,
			      .vlen = 0,
			      .params = v ? BCF_TRUE : BCF_FALSE };
	return emit_static_expr(st, cap, &e);
}

static u32 emit_bool_var(struct bcf_checker_state *st, u32 cap)
{
	struct bcf_expr e = { .code = BCF_BOOL | BCF_VAR,
			      .vlen = 0,
			      .params = 0 };
	return emit_static_expr(st, cap, &e);
}

static u32 emit_bv_val(struct bcf_checker_state *st, u32 cap, u8 width, u64 val)
{
	u32 vlen = (width + 31) / 32;
	struct bcf_expr e = { .code = BCF_BV | BCF_VAL,
			      .vlen = vlen,
			      .params = width };
	u32 id = emit_static_expr(st, cap, &e);

	for (u32 i = 0; i < vlen; i++) {
		__append_word(st, val);
		val >>= 32;
	}
	return id;
}

static u32 emit_list_from_ty(struct bcf_checker_state *st, u32 cap, u16 ty,
			     u32 elem_id)
{
	/* params copied from type ensures same_type match for lists */
	struct bcf_expr e = { .code = BCF_LIST | BCF_VAL,
			      .vlen = 1,
			      .params = ty };

	u32 id = emit_static_expr(st, cap, &e);
	__append_word(st, elem_id);
	return id;
}

static void choose_simple_arg(struct bcf_checker_state *st, u32 cap, u32 rid,
			      const struct bcf_expr_nullary *ty, u32 *out_id,
			      u32 *cache_bool, u32 *cache_bv8,
			      u32 *cache_list_bools, u32 *cache_list_bv)
{
	u8 ty_code = BCF_TYPE(ty->code);
	if (ty_code == BCF_BOOL) {
		if (*cache_bool == U32_MAX)
			*cache_bool = emit_bool_var(st, cap);
		*out_id = *cache_bool;
		return;
	}
	if (ty_code == BCF_BV) {
		u8 w = BCF_BV_WIDTH(ty->params);
		if (!w) {
			if (rid == BCF_REWRITE_BV_ITE_WIDTH_ONE ||
			    rid == BCF_REWRITE_BV_ITE_WIDTH_ONE_NOT)
				w = 1;
			else
				w = 32;
		}
		u32 val = 1;
		if (rid == BCF_REWRITE_BV_SHL_BY_CONST_0 ||
		    rid == BCF_REWRITE_BV_SHL_BY_CONST_1 ||
		    rid == BCF_REWRITE_BV_SHL_BY_CONST_2 ||
		    rid == BCF_REWRITE_BV_LSHR_BY_CONST_0 ||
		    rid == BCF_REWRITE_BV_LSHR_BY_CONST_1 ||
		    rid == BCF_REWRITE_BV_LSHR_BY_CONST_2 ||
		    rid == BCF_REWRITE_BV_ASHR_BY_CONST_0 ||
		    rid == BCF_REWRITE_BV_ASHR_BY_CONST_1 ||
		    rid == BCF_REWRITE_BV_ASHR_BY_CONST_2 ||
		    rid == BCF_REWRITE_BV_ULT_ZERO_1 ||
		    rid == BCF_REWRITE_BV_ULT_ZERO_2 ||
		    rid == BCF_REWRITE_BV_ULE_ZERO ||
		    rid == BCF_REWRITE_BV_ZERO_ULE ||
		    rid == BCF_REWRITE_BV_SHL_ZERO ||
		    rid == BCF_REWRITE_BV_LSHR_ZERO ||
		    rid == BCF_REWRITE_BV_ASHR_ZERO ||
		    rid == BCF_REWRITE_BV_ULT_ONE)
			val = 32;
		*out_id = emit_bv_val(st, cap, w, val);
		return;
	}
	if (ty_code == BCF_LIST) {
		u8 elem = BCF_LIST_TYPE(ty->params);
		if (elem == BCF_BOOL) {
			if (*cache_bool == U32_MAX)
				*cache_bool = emit_bool_var(st, cap);
			if (*cache_list_bools == U32_MAX)
				*cache_list_bools = emit_list_from_ty(
					st, cap, ty->params, *cache_bool);

			*out_id = *cache_list_bools;
			return;
		}
		if (elem == BCF_BV) {
			u16 w = BCF_LIST_TYPE_PARAM(ty->params);
			u16 ty_params = ty->params;
			if (!w) {
				w = 32;
				ty_params |= (w << 8);
			}
			u32 elem_id = emit_bv_val(st, cap, w, 8);
			*out_id =
				emit_list_from_ty(st, cap, ty_params, elem_id);
			return;
		}
	}
	/* Fallback: use a bool var for unknown/Any */
	if (*cache_bool == U32_MAX)
		*cache_bool = emit_bool_var(st, cap);
	*out_id = *cache_bool;
}

static void test_apply_rewrite_sanity(void)
{
	u32 cap = 8192;
	u32 bool_id = U32_MAX, bv8_id = U32_MAX, list_bools_id = U32_MAX,
	    list_bv_id = U32_MAX;
	struct bcf_checker_state *st = kzalloc(sizeof(*st), GFP_KERNEL);
	struct bcf_expr_ref *fact;
	u32 args[16];
	int err;
	u32 i;

	st->exprs = calloc(cap, sizeof(struct bcf_expr));
	EXPECT_TRUE(st->exprs != NULL);
	st->valid_idx = bitmap_zalloc(cap, GFP_KERNEL);
	EXPECT_TRUE(st->valid_idx != NULL);
	st->id_gen = 0;
	xa_init(&st->expr_id_map);

	/* Ensure builtins exist for _TRUE/_FALSE */
	st->true_expr = emit_bool_val(st, cap, true);
	st->false_expr = emit_bool_val(st, cap, false);
	bool_id = emit_bool_var(st, cap);

	for (i = BCF_REWRITE_BV_EXTRACT_NOT; i < __MAX_BCF_REWRITES; i++) {
		const struct bcf_rewrite *rw = bcf_rewrites[i];
		u32 a;
		EXPECT_TRUE(rw);
		if (rw->cond_len)
			continue; /* only condition-less rewrites */
		EXPECT_TRUE(rw->param_cnt);
		EXPECT_TRUE(rw->param_cnt <= ARRAY_SIZE(args));
		for (a = 0; a < rw->param_cnt; a++)
			choose_simple_arg(st, cap, i, &rw->params[a], &args[a],
					  &bool_id, &bv8_id, &list_bools_id,
					  &list_bv_id);

		st->expr_size = st->id_gen;
		fact = NULL;
		err = apply_rewrite(st, &fact, i, NULL, 0, args, rw->param_cnt);
		EXPECT_EQ(err, 0);
		if (err == 0) {
			/* Conclusion must be an equality over two terms. */
			EXPECT_TRUE(fact != NULL);
			if (fact) {
				u8 ty = BCF_TYPE(fact->expr.code);
				u8 op = BCF_OP(fact->expr.code);
				EXPECT_EQ(ty, BCF_BOOL);
				EXPECT_EQ(op, BPF_JEQ);
				EXPECT_EQ(fact->expr.vlen, 2);
			}
		}

		// free all exprs in xarray
		unsigned long expr_id;
		struct bcf_expr_ref *eref;
		xa_for_each(&st->expr_id_map, expr_id, eref) {
			kfree(eref);
		}
		xa_destroy(&st->expr_id_map);
		xa_init(&st->expr_id_map);
	}

	free_checker_state(st);
}

static struct test_case tests[] = {
	TEST_ENTRY(test_apply_rewrite_sanity),
};

int main(void)
{
	int failed = 0;
	failed |= run_tests(tests, sizeof(tests) / sizeof(tests[0]),
			    "check_rewrite");
	failed |= run_tests(expr_put_tests,
			    sizeof(expr_put_tests) / sizeof(expr_put_tests[0]),
			    "expr_put");
	failed |= run_tests(check_exprs_tests,
			    sizeof(check_exprs_tests) /
				    sizeof(check_exprs_tests[0]),
			    "check_exprs");
	failed |= run_tests(expr_equiv_tests,
			    sizeof(expr_equiv_tests) /
				    sizeof(expr_equiv_tests[0]),
			    "expr_equiv");
	failed |= run_tests(eval_tests,
			    sizeof(eval_tests) / sizeof(eval_tests[0]), "eval");
	return failed;
}
