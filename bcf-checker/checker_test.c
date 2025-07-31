#include <linux/bpf.h>
#include <linux/bcf.h>
#include <linux/bpfptr.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <linux/xarray.h>
#include <linux/slab.h>
#include <linux/refcount.h>
#include <linux/bitmap.h>
#include <linux/container_of.h>
#include <linux/bpf_verifier.h>
#include <linux/overflow.h>
#include <linux/limits.h>
#include <stdarg.h>

#include "test_utils.h"

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

extern int check_hdr(struct bcf_proof_header *hdr, union bpf_attr *attr,
		     bpfptr_t bcf_buf);
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
	return expr >= st->exprs && expr < st->exprs + st->expr_size;
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

/* Test dynamic expression with static children */
static void test_expr_put_static_children(void)
{
	struct bcf_checker_state_test st = { 0 };
	struct bcf_expr static_exprs[2] = { 0 };
	int freed_parent = 0;
	struct bcf_expr_ref_test *parent;

	xa_init(&st.expr_id_map);
	st.exprs = static_exprs;
	st.expr_size = 2;

	parent = alloc_expr_test(&st, 2, &freed_parent);
	parent->expr.args[0] = 0; /* static */
	parent->expr.args[1] = 1; /* static */

	expr_put_test(&st, &parent->expr);
	EXPECT_EQ(freed_parent, 1);

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

/* Test static expression handling */
static void test_expr_put_static(void)
{
	struct bcf_checker_state_test st = { 0 };
	struct bcf_expr static_exprs[1] = { 0 };

	st.exprs = static_exprs;
	st.expr_size = 1;

	expr_put_test(&st, &static_exprs[0]); /* should do nothing */
	EXPECT_TRUE(1); /* if we reach here, test passes */
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
	TEST_ENTRY(test_expr_put_static_children),
	TEST_ENTRY(test_expr_put_refcount),
	TEST_ENTRY(test_expr_put_static),
	TEST_ENTRY(test_expr_put_dag),
	TEST_ENTRY(test_expr_put_complex_dag),
	TEST_ENTRY(test_expr_put_deep_nested),
	TEST_ENTRY(test_expr_put_multiple_roots),
	TEST_ENTRY(test_expr_put_tree_structure),
	TEST_ENTRY(test_expr_put_mixed_static_dynamic),
	TEST_ENTRY(test_expr_put_many_references),
	TEST_ENTRY(test_expr_put_refcount_edge_cases),
};

static void test_check_hdr(void)
{
	// Helper sizes
	size_t hdr_size = sizeof(struct bcf_proof_header);
	size_t expr_size = sizeof(struct bcf_expr);
	size_t step_size = sizeof(struct bcf_proof_step);

	// --- 1. proof_size > attr->bcf_buf_size ---
	struct bcf_proof_header hdr_buf;
	struct bcf_proof_header valid_hdr = { .magic = BCF_MAGIC,
					      .expr_cnt = 1,
					      .step_cnt = 1 };
	union bpf_attr attr = { 0 };
	attr.bcf_buf_true_size = 100;
	attr.bcf_buf_size = 50;
	bpfptr_t buf = make_bpfptr((uintptr_t)&valid_hdr, 1);
	EXPECT_EQ(check_hdr(&hdr_buf, &attr, buf), -EINVAL);

	// --- 2. proof_size > MAX_BCF_PROOF_SIZE ---
	attr.bcf_buf_true_size = MAX_BCF_PROOF_SIZE + 4;
	attr.bcf_buf_size = MAX_BCF_PROOF_SIZE + 4;
	EXPECT_EQ(check_hdr(&hdr_buf, &attr, buf), -EINVAL);

	// --- 3. proof_size <= sizeof(*hdr) ---
	attr.bcf_buf_true_size = hdr_size;
	attr.bcf_buf_size = hdr_size;
	EXPECT_EQ(check_hdr(&hdr_buf, &attr, buf), -EINVAL);

	// --- 4. proof_size % sizeof(u32) != 0 ---
	attr.bcf_buf_true_size = hdr_size + 1;
	attr.bcf_buf_size = hdr_size + 1;
	EXPECT_EQ(check_hdr(&hdr_buf, &attr, buf), -EINVAL);

	attr.bcf_buf_true_size = hdr_size + expr_size + step_size;
	attr.bcf_buf_size = attr.bcf_buf_true_size;

	// --- 5. hdr->magic != BCF_MAGIC ---
	struct bcf_proof_header bad_magic = { .magic = 0x1234,
					      .expr_cnt = 1,
					      .step_cnt = 1 };
	bpfptr_t bad_magic_buf = make_bpfptr((uintptr_t)&bad_magic, 1);
	EXPECT_EQ(check_hdr(&hdr_buf, &attr, bad_magic_buf), -EINVAL);

	// --- 6. !hdr->expr_cnt ---
	struct bcf_proof_header no_expr = { .magic = BCF_MAGIC,
					    .expr_cnt = 0,
					    .step_cnt = 1 };
	bpfptr_t no_expr_buf = make_bpfptr((uintptr_t)&no_expr, 1);
	EXPECT_EQ(check_hdr(&hdr_buf, &attr, no_expr_buf), -EINVAL);

	// --- 7. !hdr->step_cnt ---
	struct bcf_proof_header no_step = { .magic = BCF_MAGIC,
					    .expr_cnt = 1,
					    .step_cnt = 0 };
	bpfptr_t no_step_buf = make_bpfptr((uintptr_t)&no_step, 1);
	EXPECT_EQ(check_hdr(&hdr_buf, &attr, no_step_buf), -EINVAL);

	// --- 8. check_mul_overflow for expr_cnt ---
	struct bcf_proof_header big_expr = { .magic = BCF_MAGIC,
					     .expr_cnt = UINT32_MAX,
					     .step_cnt = 1 };
	bpfptr_t big_expr_buf = make_bpfptr((uintptr_t)&big_expr, 1);
	EXPECT_EQ(check_hdr(&hdr_buf, &attr, big_expr_buf), -EINVAL);

	// --- 9. check_mul_overflow for step_cnt ---
	struct bcf_proof_header big_step = { .magic = BCF_MAGIC,
					     .expr_cnt = 1,
					     .step_cnt = UINT32_MAX };
	bpfptr_t big_step_buf = make_bpfptr((uintptr_t)&big_step, 1);
	EXPECT_EQ(check_hdr(&hdr_buf, &attr, big_step_buf), -EINVAL);

	// --- 10. proof_size != sizeof(*hdr) + expr_size + step_size ---
	struct bcf_proof_header valid_hdr2 = { .magic = BCF_MAGIC,
					       .expr_cnt = 2,
					       .step_cnt = 3 };
	attr.bcf_buf_true_size =
		hdr_size + 2 * expr_size + 3 * step_size + 4; // extra bytes
	attr.bcf_buf_size = attr.bcf_buf_true_size;
	bpfptr_t valid_hdr2_buf = make_bpfptr((uintptr_t)&valid_hdr2, 1);
	EXPECT_EQ(check_hdr(&hdr_buf, &attr, valid_hdr2_buf), -EINVAL);

	// --- 11. check_add_overflow for expr_size + step_size ---
	// Calculate values that will cause overflow when expr_size + step_size is computed
	// We want: expr_size + step_size > SIZE_MAX
	// where expr_size = expr_cnt * sizeof(struct bcf_expr)
	// and step_size = step_cnt * sizeof(struct bcf_proof_step)
	size_t max_expr_cnt = SIZE_MAX / expr_size;
	size_t max_step_cnt = SIZE_MAX / step_size;

	// Use values that when multiplied and added will overflow
	struct bcf_proof_header overflow_hdr = { .magic = BCF_MAGIC,
						 .expr_cnt = max_expr_cnt,
						 .step_cnt = max_step_cnt };
	attr.bcf_buf_true_size =
		hdr_size + 1; // Large enough to pass other checks
	attr.bcf_buf_size = attr.bcf_buf_true_size;
	bpfptr_t overflow_buf = make_bpfptr((uintptr_t)&overflow_hdr, 1);
	EXPECT_EQ(check_hdr(&hdr_buf, &attr, overflow_buf), -EINVAL);

	// --- 12. Valid case ---
	struct bcf_proof_header valid_hdr3 = { .magic = BCF_MAGIC,
					       .expr_cnt = 2,
					       .step_cnt = 3 };
	attr.bcf_buf_true_size = hdr_size + 2 * expr_size + 3 * step_size;
	attr.bcf_buf_size = attr.bcf_buf_true_size;
	bpfptr_t valid_hdr3_buf = make_bpfptr((uintptr_t)&valid_hdr3, 1);
	EXPECT_EQ(check_hdr(&hdr_buf, &attr, valid_hdr3_buf), 0);
}

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

	/* Expression buffer */
	struct {
		u8 code;
		u8 vlen;
		u16 params;
		u32 args[U8_MAX];
	} expr_buf;

	/* Stack for expr equiv comparison */
	struct bcf_cmp_state expr_stack[BCF_MAX_CMP_STACK];
};

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

static void free_checker_state_test(struct bcf_checker_state *st)
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
}

static void run_check_exprs_test(void *buf, size_t buf_sz, int expected)
{
	struct bcf_checker_state st = { 0 };
	bpfptr_t bptr = make_bpfptr((uintptr_t)buf, 1);
	int err;

	xa_init(&st.expr_id_map);
	err = check_exprs(&st, bptr, buf_sz / sizeof(struct bcf_expr));
	EXPECT_EQ(err, expected);
	free_checker_state_test(&st);
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

static void test_check_exprs_invalid_bv_size(void)
{
	CHECK_EXPRS_EXPECT(u32 v0 = emit(BCF_BV_VAR32);
			   u32 bad = emit_variadic_expr(BCF_BV | BCF_BVSIZE, 1,
							24, emit_buf, &emit_off,
							v0);
			   , -EINVAL);
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
	TEST_ENTRY(test_check_exprs_invalid_bv_size),
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
			  u32 idx1 = emit(BCF_BV_VAR32);, idx0, idx1, 1);
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
		u32 bbt0 = emit_variadic_expr(BCF_BV | BCF_FROM_BOOL, 2, 32, emit_buf,
					      &emit_off, b0, b1);
		u32 x0 = emit(BCF_BOOL_VAR); u32 x1 = emit(BCF_BOOL_VAR);
		u32 bbt1 = emit_variadic_expr(BCF_BV | BCF_FROM_BOOL, 2, 32, emit_buf,
					      &emit_off, x0, x1);
		, bbt0, bbt1, 0);
	EXPR_EQUIV_EXPECT(
		u32 b0 = emit(BCF_BOOL_VAR); u32 b1 = emit(BCF_BOOL_VAR);
		u32 bbt0 = emit_variadic_expr(BCF_BV | BCF_FROM_BOOL, 2, 32, emit_buf,
					      &emit_off, b0, b1);
		u32 bbt1 = emit_variadic_expr(BCF_BV | BCF_FROM_BOOL, 2, 32, emit_buf,
					      &emit_off, b0, b1);
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

static struct test_case tests[] = {
	TEST_ENTRY(test_check_hdr),
};

int main(void)
{
	int failed = 0;
	failed |=
		run_tests(tests, sizeof(tests) / sizeof(tests[0]), "check_hdr");
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
	return failed;
}
