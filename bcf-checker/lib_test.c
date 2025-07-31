#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/xarray.h>
#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/refcount.h>

#include "test_utils.h"

struct test_item {
	int id;
	char data[32];
};

static int xarray_test_count;
static int bitmap_test_count;

/* ==================== XARRAY TESTS ==================== */

static void test_xarray_basic_operations(void)
{
	struct xarray xa;
	struct test_item *item1, *item2, *item3;
	void *ret;

	xa_init(&xa);

	/* Initialize test items */
	item1 = kmalloc(sizeof(*item1), GFP_KERNEL);
	item2 = kmalloc(sizeof(*item2), GFP_KERNEL);
	item3 = kmalloc(sizeof(*item3), GFP_KERNEL);

	item1->id = 1;
	strcpy(item1->data, "item1");
	item2->id = 2;
	strcpy(item2->data, "item2");
	item3->id = 3;
	strcpy(item3->data, "item3");

	/* Test store and load */
	ret = xa_store(&xa, 0, item1, GFP_KERNEL);
	EXPECT_TRUE(!ret); /* Should return NULL for new entry */

	ret = xa_load(&xa, 0);
	EXPECT_TRUE(ret == item1);

	/* Test store at different indices */
	xa_store(&xa, 100, item2, GFP_KERNEL);
	xa_store(&xa, 1000, item3, GFP_KERNEL);

	ret = xa_load(&xa, 100);
	EXPECT_TRUE(ret == item2);
	ret = xa_load(&xa, 1000);
	EXPECT_TRUE(ret == item3);

	/* Test overwrite */
	ret = xa_store(&xa, 0, item2, GFP_KERNEL);
	EXPECT_TRUE(ret == item1); /* Should return old value */
	ret = xa_load(&xa, 0);
	EXPECT_TRUE(ret == item2);

	/* Test erase */
	ret = xa_erase(&xa, 100);
	EXPECT_TRUE(ret == item2);
	ret = xa_load(&xa, 100);
	EXPECT_TRUE(!ret);

	/* Test non-existent index */
	ret = xa_load(&xa, 999);
	EXPECT_TRUE(!ret);

	/* Cleanup */
	xa_destroy(&xa);
	kfree(item1);
	kfree(item2);
	kfree(item3);

	xarray_test_count++;
}

static void test_xarray_marks(void)
{
	struct xarray xa;
	struct test_item *item;

	xa_init(&xa);

	item = kmalloc(sizeof(*item), GFP_KERNEL);
	item->id = 1;
	strcpy(item->data, "marked_item");

	/* Store item */
	xa_store(&xa, 42, item, GFP_KERNEL);

	/* Test initial mark state */
	EXPECT_TRUE(!xa_get_mark(&xa, 42, XA_MARK_0));
	EXPECT_TRUE(!xa_get_mark(&xa, 42, XA_MARK_1));
	EXPECT_TRUE(!xa_get_mark(&xa, 42, XA_MARK_2));

	/* Set marks */
	xa_set_mark(&xa, 42, XA_MARK_0);
	xa_set_mark(&xa, 42, XA_MARK_1);

	EXPECT_TRUE(xa_get_mark(&xa, 42, XA_MARK_0));
	EXPECT_TRUE(xa_get_mark(&xa, 42, XA_MARK_1));
	EXPECT_TRUE(!xa_get_mark(&xa, 42, XA_MARK_2));

	/* Clear marks */
	xa_clear_mark(&xa, 42, XA_MARK_0);
	EXPECT_TRUE(!xa_get_mark(&xa, 42, XA_MARK_0));
	EXPECT_TRUE(xa_get_mark(&xa, 42, XA_MARK_1));

	/* Test marks on non-existent entry */
	EXPECT_TRUE(!xa_get_mark(&xa, 999, XA_MARK_0));
	xa_set_mark(&xa, 999, XA_MARK_0);
	EXPECT_TRUE(!xa_get_mark(&xa, 999, XA_MARK_0));

	/* Cleanup */
	xa_destroy(&xa);
	kfree(item);

	xarray_test_count++;
}

static void test_xarray_values(void)
{
	struct xarray xa;
	void *ret;

	xa_init(&xa);

	/* Test value entries */
	xa_store(&xa, 0, xa_mk_value(42), GFP_KERNEL);
	xa_store(&xa, 1, xa_mk_value(123), GFP_KERNEL);
	xa_store(&xa, 2, xa_mk_value(0xdeadbeef), GFP_KERNEL);

	ret = xa_load(&xa, 0);
	EXPECT_TRUE(xa_is_value(ret));
	EXPECT_EQ(xa_to_value(ret), 42);

	ret = xa_load(&xa, 1);
	EXPECT_TRUE(xa_is_value(ret));
	EXPECT_EQ(xa_to_value(ret), 123);

	ret = xa_load(&xa, 2);
	EXPECT_TRUE(xa_is_value(ret));
	EXPECT_EQ(xa_to_value(ret), 0xdeadbeef);

	/* Test tagged pointers */
	void *ptr = (void *)0xffff888012345670UL;

	xa_store(&xa, 10, xa_tag_pointer(ptr, 1), GFP_KERNEL);

	ret = xa_load(&xa, 10);
	EXPECT_TRUE(!xa_is_value(xa_untag_pointer(ret)));
	EXPECT_TRUE(!xa_is_internal(ret));
	EXPECT_EQ(xa_untag_pointer(ret), ptr);
	EXPECT_EQ(xa_pointer_tag(ret), 1);

	/* Cleanup */
	xa_destroy(&xa);

	xarray_test_count++;
}

static void test_xarray_iteration(void)
{
	struct xarray xa;
	unsigned long index;
	void *entry;
	int count = 0;

	xa_init(&xa);

	/* Store some entries */
	xa_store(&xa, 10, xa_mk_value(10), GFP_KERNEL);
	xa_store(&xa, 20, xa_mk_value(20), GFP_KERNEL);
	xa_store(&xa, 30, xa_mk_value(30), GFP_KERNEL);
	xa_store(&xa, 40, xa_mk_value(40), GFP_KERNEL);

	/* Test xa_find */
	index = 0;
	entry = xa_find(&xa, &index, ULONG_MAX, XA_PRESENT);
	EXPECT_TRUE(entry);
	EXPECT_EQ(index, 10);
	EXPECT_EQ(xa_to_value(entry), 10);

	/* Test xa_find_after */
	index = 10;
	entry = xa_find_after(&xa, &index, ULONG_MAX, XA_PRESENT);
	EXPECT_TRUE(entry);
	EXPECT_EQ(index, 20);
	EXPECT_EQ(xa_to_value(entry), 20);

	/* Test iteration with xa_for_each */
	xa_for_each(&xa, index, entry) {
		EXPECT_TRUE(xa_is_value(entry));
		EXPECT_EQ(xa_to_value(entry), index);
		count++;
	}
	EXPECT_EQ(count, 4);

	/* Test iteration with marks */
	xa_set_mark(&xa, 20, XA_MARK_0);
	xa_set_mark(&xa, 40, XA_MARK_0);

	count = 0;
	xa_for_each_marked(&xa, index, entry, XA_MARK_0) {
		EXPECT_TRUE(xa_is_value(entry));
		EXPECT_EQ(xa_to_value(entry), index);
		count++;
	}
	EXPECT_EQ(count, 2);

	/* Cleanup */
	xa_destroy(&xa);

	xarray_test_count++;
}

static void test_xarray_limits(void)
{
	struct xarray xa;
	void *ret;
	unsigned long large_index = 1UL << 30; /* Large index */

	xa_init(&xa);

	/* Test very large indices */
	ret = xa_store(&xa, large_index, xa_mk_value(42), GFP_KERNEL);
	EXPECT_TRUE(!ret);

	ret = xa_load(&xa, large_index);
	EXPECT_TRUE(xa_is_value(ret));
	EXPECT_EQ(xa_to_value(ret), 42);

	/* Test zero index */
	xa_store(&xa, 0, xa_mk_value(0), GFP_KERNEL);
	ret = xa_load(&xa, 0);
	EXPECT_TRUE(xa_is_value(ret));
	EXPECT_EQ(xa_to_value(ret), 0);

	/* Test empty array */
	EXPECT_TRUE(!xa_empty(&xa));

	/* Cleanup */
	xa_destroy(&xa);

	xarray_test_count++;
}

static void test_xarray_alloc(void)
{
	struct xarray xa;
	u32 id;
	int ret;

	xa_init_flags(&xa, XA_FLAGS_ALLOC);

	/* Test basic allocation */
	ret = xa_alloc(&xa, &id, xa_mk_value(100), xa_limit_32b, GFP_KERNEL);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(id, 0);

	ret = xa_alloc(&xa, &id, xa_mk_value(200), xa_limit_32b, GFP_KERNEL);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(id, 1);

	ret = xa_alloc(&xa, &id, xa_mk_value(300), xa_limit_32b, GFP_KERNEL);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(id, 2);

	/* Test that allocated entries are present */
	EXPECT_EQ(xa_to_value(xa_load(&xa, 0)), 100);
	EXPECT_EQ(xa_to_value(xa_load(&xa, 1)), 200);
	EXPECT_EQ(xa_to_value(xa_load(&xa, 2)), 300);

	/* Test allocation after deletion */
	xa_erase(&xa, 1);
	ret = xa_alloc(&xa, &id, xa_mk_value(400), xa_limit_32b, GFP_KERNEL);
	EXPECT_EQ(ret, 0);
	EXPECT_EQ(id, 1); /* Should reuse the freed ID */

	/* Cleanup */
	xa_destroy(&xa);

	xarray_test_count++;
}

/* ==================== BITMAP TESTS ==================== */

static void test_bitmap_basic_operations(void)
{
	DECLARE_BITMAP(bitmap, 128);
	DECLARE_BITMAP(bitmap2, 128);

	/* Test initialization */
	bitmap_zero(bitmap, 128);
	EXPECT_TRUE(bitmap_empty(bitmap, 128));
	EXPECT_EQ(bitmap_weight(bitmap, 128), 0);

	/* Test setting bits */
	bitmap_set(bitmap, 0, 1);
	EXPECT_TRUE(test_bit(0, bitmap));
	EXPECT_EQ(bitmap_weight(bitmap, 128), 1);

	bitmap_set(bitmap, 63, 1);
	EXPECT_TRUE(test_bit(63, bitmap));
	EXPECT_EQ(bitmap_weight(bitmap, 128), 2);

	bitmap_set(bitmap, 64, 1);
	EXPECT_TRUE(test_bit(64, bitmap));
	EXPECT_EQ(bitmap_weight(bitmap, 128), 3);

	/* Test clearing bits */
	bitmap_clear(bitmap, 0, 1);
	EXPECT_TRUE(!test_bit(0, bitmap));
	EXPECT_EQ(bitmap_weight(bitmap, 128), 2);

	/* Test setting ranges */
	bitmap_set(bitmap, 10, 5);
	EXPECT_TRUE(test_bit(10, bitmap));
	EXPECT_TRUE(test_bit(11, bitmap));
	EXPECT_TRUE(test_bit(12, bitmap));
	EXPECT_TRUE(test_bit(13, bitmap));
	EXPECT_TRUE(test_bit(14, bitmap));
	EXPECT_TRUE(!test_bit(15, bitmap));
	EXPECT_EQ(bitmap_weight(bitmap, 128), 7);

	/* Test clearing ranges */
	bitmap_clear(bitmap, 11, 3);
	EXPECT_TRUE(test_bit(10, bitmap));
	EXPECT_TRUE(!test_bit(11, bitmap));
	EXPECT_TRUE(!test_bit(12, bitmap));
	EXPECT_TRUE(!test_bit(13, bitmap));
	EXPECT_TRUE(test_bit(14, bitmap));
	EXPECT_EQ(bitmap_weight(bitmap, 128), 4);

	/* Test fill */
	bitmap_fill(bitmap2, 128);
	EXPECT_TRUE(bitmap_full(bitmap2, 128));
	EXPECT_EQ(bitmap_weight(bitmap2, 128), 128);

	bitmap_test_count++;
}

static void test_bitmap_find_operations(void)
{
	DECLARE_BITMAP(bitmap, 256);
	unsigned long pos;

	/* Initialize with some bits set */
	bitmap_zero(bitmap, 256);
	bitmap_set(bitmap, 10, 1);
	bitmap_set(bitmap, 50, 1);
	bitmap_set(bitmap, 100, 1);
	bitmap_set(bitmap, 150, 1);
	bitmap_set(bitmap, 200, 1);

	/* Test find_first_bit */
	pos = find_first_bit(bitmap, 256);
	EXPECT_EQ(pos, 10);

	/* Test find_next_bit */
	pos = find_next_bit(bitmap, 256, 11);
	EXPECT_EQ(pos, 50);

	pos = find_next_bit(bitmap, 256, 51);
	EXPECT_EQ(pos, 100);

	pos = find_next_bit(bitmap, 256, 201);
	EXPECT_EQ(pos, 256); /* Should return size when no more bits */

	/* Test find_first_zero_bit */
	bitmap_fill(bitmap, 256);
	bitmap_clear(bitmap, 25, 1);
	bitmap_clear(bitmap, 75, 1);
	bitmap_clear(bitmap, 125, 1);

	pos = find_first_zero_bit(bitmap, 256);
	EXPECT_EQ(pos, 25);

	pos = find_next_zero_bit(bitmap, 256, 26);
	EXPECT_EQ(pos, 75);

	pos = find_next_zero_bit(bitmap, 256, 76);
	EXPECT_EQ(pos, 125);

	bitmap_test_count++;
}

static void test_bitmap_logical_operations(void)
{
	DECLARE_BITMAP(bitmap1, 128);
	DECLARE_BITMAP(bitmap2, 128);
	DECLARE_BITMAP(result, 128);

	/* Initialize bitmaps */
	bitmap_zero(bitmap1, 128);
	bitmap_zero(bitmap2, 128);
	bitmap_zero(result, 128);

	/* Set some bits in bitmap1 */
	bitmap_set(bitmap1, 0, 1);
	bitmap_set(bitmap1, 10, 1);
	bitmap_set(bitmap1, 20, 1);
	bitmap_set(bitmap1, 30, 1);

	/* Set some bits in bitmap2 */
	bitmap_set(bitmap2, 10, 1);
	bitmap_set(bitmap2, 20, 1);
	bitmap_set(bitmap2, 40, 1);
	bitmap_set(bitmap2, 50, 1);

	/* Test OR operation */
	bitmap_or(result, bitmap1, bitmap2, 128);
	EXPECT_TRUE(test_bit(0, result));
	EXPECT_TRUE(test_bit(10, result));
	EXPECT_TRUE(test_bit(20, result));
	EXPECT_TRUE(test_bit(30, result));
	EXPECT_TRUE(test_bit(40, result));
	EXPECT_TRUE(test_bit(50, result));
	EXPECT_EQ(bitmap_weight(result, 128), 6);

	/* Test AND operation */
	bitmap_zero(result, 128);
	bitmap_and(result, bitmap1, bitmap2, 128);
	EXPECT_TRUE(!test_bit(0, result));
	EXPECT_TRUE(test_bit(10, result));
	EXPECT_TRUE(test_bit(20, result));
	EXPECT_TRUE(!test_bit(30, result));
	EXPECT_TRUE(!test_bit(40, result));
	EXPECT_TRUE(!test_bit(50, result));
	EXPECT_EQ(bitmap_weight(result, 128), 2);

	/* Test intersection check */
	EXPECT_TRUE(bitmap_intersects(bitmap1, bitmap2, 128));

	/* Test equality */
	bitmap_zero(result, 128);
	bitmap_copy(result, bitmap1, 128);
	EXPECT_TRUE(bitmap_equal(bitmap1, result, 128));

	/* Test non-intersecting bitmaps */
	bitmap_zero(bitmap2, 128);
	bitmap_set(bitmap2, 100, 1);
	bitmap_set(bitmap2, 110, 1);
	EXPECT_TRUE(!bitmap_intersects(bitmap1, bitmap2, 128));

	bitmap_test_count++;
}

static void test_bitmap_edge_cases(void)
{
	DECLARE_BITMAP(bitmap, 64);
	unsigned long pos;

	/* Test empty bitmap */
	bitmap_zero(bitmap, 64);
	pos = find_first_bit(bitmap, 64);
	EXPECT_EQ(pos, 64);

	pos = find_first_zero_bit(bitmap, 64);
	EXPECT_EQ(pos, 0);

	/* Test full bitmap */
	bitmap_fill(bitmap, 64);
	pos = find_first_bit(bitmap, 64);
	EXPECT_EQ(pos, 0);

	pos = find_first_zero_bit(bitmap, 64);
	EXPECT_EQ(pos, 64);

	/* Test single bit operations */
	bitmap_zero(bitmap, 64);
	bitmap_set(bitmap, 0, 1);
	EXPECT_EQ(bitmap_weight(bitmap, 64), 1);
	EXPECT_TRUE(test_bit(0, bitmap));

	bitmap_clear(bitmap, 0, 1);
	EXPECT_EQ(bitmap_weight(bitmap, 64), 0);
	EXPECT_TRUE(!test_bit(0, bitmap));

	/* Test boundary conditions */
	bitmap_zero(bitmap, 64);
	bitmap_set(bitmap, 63, 1);
	EXPECT_TRUE(test_bit(63, bitmap));
	EXPECT_EQ(bitmap_weight(bitmap, 64), 1);

	/* Test range operations at boundaries */
	bitmap_zero(bitmap, 64);
	bitmap_set(bitmap, 60, 4);
	EXPECT_TRUE(test_bit(60, bitmap));
	EXPECT_TRUE(test_bit(61, bitmap));
	EXPECT_TRUE(test_bit(62, bitmap));
	EXPECT_TRUE(test_bit(63, bitmap));
	EXPECT_EQ(bitmap_weight(bitmap, 64), 4);

	bitmap_clear(bitmap, 60, 4);
	EXPECT_EQ(bitmap_weight(bitmap, 64), 0);

	bitmap_test_count++;
}

static void test_bitmap_string_operations(void)
{
	DECLARE_BITMAP(bitmap, 64);
	char buf[256];
	size_t len;

	/* Test empty bitmap */
	bitmap_zero(bitmap, 64);
	len = bitmap_scnprintf(bitmap, 64, buf, sizeof(buf));
	EXPECT_EQ(len, 0);

	/* Test single bit */
	bitmap_set(bitmap, 10, 1);
	len = bitmap_scnprintf(bitmap, 64, buf, sizeof(buf));
	EXPECT_EQ(len, 2); /* "10" */
	EXPECT_TRUE(!strcmp(buf, "10"));

	/* Test multiple bits */
	bitmap_zero(bitmap, 64);
	bitmap_set(bitmap, 5, 1);
	bitmap_set(bitmap, 10, 1);
	bitmap_set(bitmap, 15, 1);
	len = bitmap_scnprintf(bitmap, 64, buf, sizeof(buf));
	EXPECT_EQ(len, strlen("5,10,15")); /* "5,10,15" */
	EXPECT_TRUE(!strcmp(buf, "5,10,15"));

	/* Test consecutive bits (should show as range) */
	bitmap_zero(bitmap, 64);
	bitmap_set(bitmap, 10, 1);
	bitmap_set(bitmap, 11, 1);
	bitmap_set(bitmap, 12, 1);
	len = bitmap_scnprintf(bitmap, 64, buf, sizeof(buf));
	EXPECT_EQ(len, 5); /* "10-12" */
	EXPECT_TRUE(!strcmp(buf, "10-12"));

	/* Test mixed ranges and singles */
	bitmap_zero(bitmap, 64);
	bitmap_set(bitmap, 5, 1);
	bitmap_set(bitmap, 10, 1);
	bitmap_set(bitmap, 11, 1);
	bitmap_set(bitmap, 12, 1);
	bitmap_set(bitmap, 20, 1);
	len = bitmap_scnprintf(bitmap, 64, buf, sizeof(buf));
	EXPECT_EQ(len, strlen("5,10-12,20")); /* "5,10-12,20" */
	EXPECT_TRUE(!strcmp(buf, "5,10-12,20"));

	bitmap_test_count++;
}

static void test_bitmap_memory_operations(void)
{
	unsigned long *bitmap1, *bitmap2, *bitmap3;
	int bits = 256;

	/* Test allocation */
	bitmap1 = bitmap_zalloc(bits, GFP_KERNEL);
	EXPECT_TRUE(bitmap1);

	bitmap2 = bitmap_zalloc(bits, GFP_KERNEL);
	EXPECT_TRUE(bitmap2);
	EXPECT_EQ(bitmap_weight(bitmap2, bits), 0);

	/* Test operations on allocated bitmaps */
	bitmap_set(bitmap1, 0, 1);
	bitmap_set(bitmap1, 100, 1);
	bitmap_set(bitmap1, 200, 1);

	bitmap_set(bitmap2, 100, 1);
	bitmap_set(bitmap2, 150, 1);

	bitmap3 = bitmap_zalloc(bits, GFP_KERNEL);
	EXPECT_TRUE(bitmap3);

	bitmap_or(bitmap3, bitmap1, bitmap2, bits);
	EXPECT_EQ(bitmap_weight(bitmap3, bits), 4);

	/* Test intersection */
	EXPECT_TRUE(bitmap_intersects(bitmap1, bitmap2, bits));

	/* Test equality */
	bitmap_copy(bitmap3, bitmap1, bits);
	EXPECT_TRUE(bitmap_equal(bitmap1, bitmap3, bits));

	/* Cleanup */
	bitmap_free(bitmap1);
	bitmap_free(bitmap2);
	bitmap_free(bitmap3);

	bitmap_test_count++;
}

/* ==================== ATOMIC TESTS ==================== */

static void test_atomic_basic_operations(void)
{
	atomic_t v = ATOMIC_INIT(0);

	/* Test atomic_set and atomic_read */
	atomic_set(&v, 42);
	EXPECT_EQ(atomic_read(&v), 42);

	/* Test atomic_inc */
	atomic_inc(&v);
	EXPECT_EQ(atomic_read(&v), 43);

	/* Test atomic_dec_and_test (should not be zero) */
	EXPECT_TRUE(!atomic_dec_and_test(&v));
	EXPECT_EQ(atomic_read(&v), 42);

	/* Decrement to zero */
	atomic_set(&v, 1);
	EXPECT_TRUE(atomic_dec_and_test(&v));
	EXPECT_EQ(atomic_read(&v), 0);
}

static void test_atomic_cmpxchg(void)
{
	atomic_t v = ATOMIC_INIT(100);
	int old;

	/* Successful cmpxchg */
	old = atomic_cmpxchg(&v, 100, 200);
	EXPECT_EQ(old, 100);
	EXPECT_EQ(atomic_read(&v), 200);

	/* Failed cmpxchg (value not matching) */
	old = atomic_cmpxchg(&v, 100, 300);
	EXPECT_EQ(old, 200);
	EXPECT_EQ(atomic_read(&v), 200);
}

static void test_atomic_try_cmpxchg(void)
{
	atomic_t v = ATOMIC_INIT(50);
	int expect = 50;
	int ret;

	/* Should succeed */
	ret = atomic_try_cmpxchg(&v, &expect, 123);
	EXPECT_TRUE(ret);
	EXPECT_EQ(atomic_read(&v), 123);
	EXPECT_EQ(expect, 50);

	/* Should fail (value not matching) */
	expect = 999;
	ret = atomic_try_cmpxchg(&v, &expect, 456);
	EXPECT_TRUE(!ret);
	EXPECT_EQ(atomic_read(&v), 123);
	EXPECT_EQ(expect, 123);
}

static void test_atomic_fetch_add_sub(void)
{
	atomic_t v = ATOMIC_INIT(10);
	int old;

	/* atomic_fetch_add_relaxed */
	old = atomic_fetch_add_relaxed(5, &v);
	EXPECT_EQ(old, 10);
	EXPECT_EQ(atomic_read(&v), 15);

	/* atomic_fetch_sub_release */
	old = atomic_fetch_sub_release(3, &v);
	EXPECT_EQ(old, 15); // atomic_fetch_sub_release returns new value
	EXPECT_EQ(atomic_read(&v), 12);
}

static void test_atomic_set_release(void)
{
	atomic_t v = ATOMIC_INIT(0);
	atomic_set_release(&v, 77);
	EXPECT_EQ(atomic_read(&v), 77);
}

static struct test_case atomic_tests[] = {
	TEST_ENTRY(test_atomic_basic_operations),
	TEST_ENTRY(test_atomic_cmpxchg),
	TEST_ENTRY(test_atomic_try_cmpxchg),
	TEST_ENTRY(test_atomic_fetch_add_sub),
	TEST_ENTRY(test_atomic_set_release),
};

/* ==================== REFCOUNT TESTS ==================== */

static void test_refcount_basic_operations(void)
{
	refcount_t r = REFCOUNT_INIT(0);

	/* Test refcount_set and refcount_read */
	refcount_set(&r, 10);
	EXPECT_EQ(refcount_read(&r), 10);

	/* Test refcount_inc */
	refcount_inc(&r);
	EXPECT_EQ(refcount_read(&r), 11);

	/* Test refcount_dec_and_test (should not be zero) */
	EXPECT_TRUE(!refcount_dec_and_test(&r));
	EXPECT_EQ(refcount_read(&r), 10);

	/* Decrement to zero */
	refcount_set(&r, 1);
	EXPECT_TRUE(refcount_dec_and_test(&r));
	EXPECT_EQ(refcount_read(&r), 0);
}

static void test_refcount_add_and_sub(void)
{
	refcount_t r = REFCOUNT_INIT(5);

	refcount_add(3, &r);
	EXPECT_EQ(refcount_read(&r), 8);

	EXPECT_TRUE(!refcount_sub_and_test(3, &r));
	EXPECT_EQ(refcount_read(&r), 5);

	EXPECT_TRUE(refcount_sub_and_test(5, &r));
	EXPECT_EQ(refcount_read(&r), 0);
}

static void test_refcount_inc_not_zero(void)
{
	refcount_t r = REFCOUNT_INIT(2);
	bool ret;

	ret = refcount_inc_not_zero(&r);
	EXPECT_TRUE(ret);
	EXPECT_EQ(refcount_read(&r), 3);

	refcount_set(&r, 0);
	ret = refcount_inc_not_zero(&r);
	EXPECT_TRUE(!ret);
	EXPECT_EQ(refcount_read(&r), 0);
}

static void test_refcount_add_not_zero(void)
{
	refcount_t r = REFCOUNT_INIT(4);
	bool ret;

	ret = refcount_add_not_zero(2, &r);
	EXPECT_TRUE(ret);
	EXPECT_EQ(refcount_read(&r), 6);

	refcount_set(&r, 0);
	ret = refcount_add_not_zero(3, &r);
	EXPECT_TRUE(!ret);
	EXPECT_EQ(refcount_read(&r), 0);
}

static void test_refcount_set_release(void)
{
	refcount_t r = REFCOUNT_INIT(0);
	refcount_set_release(&r, 99);
	EXPECT_EQ(refcount_read(&r), 99);
}

static struct test_case refcount_tests[] = {
	TEST_ENTRY(test_refcount_basic_operations),
	TEST_ENTRY(test_refcount_add_and_sub),
	TEST_ENTRY(test_refcount_inc_not_zero),
	TEST_ENTRY(test_refcount_add_not_zero),
	TEST_ENTRY(test_refcount_set_release),
};

/* ==================== MAIN TEST RUNNER ==================== */

static struct test_case xarray_tests[] = {
	TEST_ENTRY(test_xarray_basic_operations),
	TEST_ENTRY(test_xarray_marks),
	TEST_ENTRY(test_xarray_values),
	TEST_ENTRY(test_xarray_iteration),
	TEST_ENTRY(test_xarray_limits),
	TEST_ENTRY(test_xarray_alloc),
};

static struct test_case bitmap_tests[] = {
	TEST_ENTRY(test_bitmap_basic_operations),
	TEST_ENTRY(test_bitmap_find_operations),
	TEST_ENTRY(test_bitmap_logical_operations),
	TEST_ENTRY(test_bitmap_edge_cases),
	TEST_ENTRY(test_bitmap_string_operations),
	TEST_ENTRY(test_bitmap_memory_operations),
};

int main(void)
{
	int xarray_failed, bitmap_failed, atomic_failed, refcount_failed;

	TEST_PRINTF("Starting XArray and Bitmap tests...\n\n");

	/* Run XArray tests */
	xarray_failed =
		run_tests(xarray_tests, ARRAY_SIZE(xarray_tests), "XArray");

	TEST_PRINTF("\n");

	/* Run Bitmap tests */
	bitmap_failed =
		run_tests(bitmap_tests, ARRAY_SIZE(bitmap_tests), "Bitmap");

	TEST_PRINTF("\n");

	/* Run Atomic tests */
	atomic_failed =
		run_tests(atomic_tests, ARRAY_SIZE(atomic_tests), "Atomic");

	/* Run Refcount tests */
	refcount_failed = run_tests(refcount_tests, ARRAY_SIZE(refcount_tests),
				    "Refcount");

	return (xarray_failed || bitmap_failed || atomic_failed ||
		refcount_failed) ?
		       1 :
		       0;
}
