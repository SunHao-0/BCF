#ifndef __LINUX_TEST_UTILS_H__
#define __LINUX_TEST_UTILS_H__

#include <stdio.h>

#ifndef TEST_PRINTF
#define TEST_PRINTF(fmt, ...) printf(fmt, ##__VA_ARGS__)
#endif
#ifndef TEST_WARN
#define TEST_WARN(fmt, ...) printf(fmt, ##__VA_ARGS__)
#endif

#define EXPECT_EQ(a, b)                                                               \
	do {                                                                          \
		if ((a) != (b)) {                                                     \
			TEST_WARN(                                                    \
				"[FAIL] %s:%d: %s == %s (got %lld, expected %lld)\n", \
				__FILE__, __LINE__, #a, #b, (long long)(a),           \
				(long long)(b));                                      \
			test_failures++;                                              \
		}                                                                     \
	} while (0)

#define EXPECT_TRUE(cond)                                                   \
	do {                                                                \
		if (!(cond)) {                                              \
			TEST_WARN("[FAIL] %s:%d: %s\n", __FILE__, __LINE__, \
				  #cond);                                   \
			test_failures++;                                    \
		}                                                           \
	} while (0)

struct test_case {
	const char *name;
	void (*fn)(void);
};

#define TEST_ENTRY(fn) { #fn, fn }

static int test_failures = 0;

static inline int run_tests(const struct test_case *tests, int num_tests,
			    const char *suite_name)
{
	int failed = 0;
	TEST_PRINTF("Running %d %s tests...\n", num_tests, suite_name);
	for (int i = 0; i < num_tests; ++i) {
		int before = test_failures;
		tests[i].fn();
		if (test_failures > before) {
			TEST_PRINTF("[FAIL] %s\n", tests[i].name);
			failed++;
		} else {
			TEST_PRINTF("[PASS] %s\n", tests[i].name);
		}
	}
	TEST_PRINTF("\nTest summary: %d/%d passed, %d failed\n",
		    num_tests - failed, num_tests, failed);
	return failed ? 1 : 0;
}

#endif // __LINUX_TEST_UTILS_H__