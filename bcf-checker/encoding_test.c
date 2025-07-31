#include <uapi/linux/bcf.h>
#include <linux/bpf.h>
#include <linux/bcf.h>

#include "test_utils.h"

static void test_bv_var(void)
{
	struct bcf_expr bv32 = BCF_BV_VAR32;
	EXPECT_EQ(bv32.code, (BCF_BV | BCF_VAR));
	EXPECT_EQ(bv32.vlen, 0);
	EXPECT_EQ(BCF_BV_WIDTH(bv32.params), 32);
	EXPECT_EQ((bv32.params & 0xff00), 0);

	struct bcf_expr bv64 = BCF_BV_VAR64;
	EXPECT_EQ(bv64.code, (BCF_BV | BCF_VAR));
	EXPECT_EQ(bv64.vlen, 0);
	EXPECT_EQ(BCF_BV_WIDTH(bv64.params), 64);
	EXPECT_EQ((bv64.params & 0xff00), 0);
}

static void test_bv_val(void)
{
	struct bcf_expr_unary val32 = BCF_BV_VAL32(0x12345678);
	EXPECT_EQ(val32.code, (BCF_BV | BCF_VAL));
	EXPECT_EQ(val32.vlen, 1);
	EXPECT_EQ(BCF_BV_WIDTH(val32.params), 32);
	EXPECT_EQ((val32.params & 0xff00), 0);
	EXPECT_EQ(val32.arg0, 0x12345678);

	struct bcf_expr_binary val64 = BCF_BV_VAL64(0x123456789abcdef0ULL);
	EXPECT_EQ(val64.code, (BCF_BV | BCF_VAL));
	EXPECT_EQ(val64.vlen, 2);
	EXPECT_EQ(BCF_BV_WIDTH(val64.params), 64);
	EXPECT_EQ((val64.params & 0xff00), 0);
	EXPECT_EQ(val64.arg0, 0x9abcdef0);
	EXPECT_EQ(val64.arg1, 0x12345678);
}

static void test_bv_extract(void)
{
	struct bcf_expr_unary extract = BCF_BV_EXTRACT(8, 42);
	EXPECT_EQ(extract.code, (BCF_BV | BCF_EXTRACT));
	EXPECT_EQ(extract.vlen, 1);
	EXPECT_EQ(BCF_EXTRACT_START(extract.params), 7);
	EXPECT_EQ(BCF_EXTRACT_END(extract.params), 0);
	EXPECT_EQ(extract.arg0, 42);
}

static void test_bv_ext(void)
{
	struct bcf_expr_unary zext = BCF_BV_ZEXT(16, 8, 99);
	EXPECT_EQ(zext.code, (BCF_BV | BCF_ZERO_EXTEND));
	EXPECT_EQ(zext.vlen, 1);
	EXPECT_EQ(BCF_BV_WIDTH(zext.params), 16);
	EXPECT_EQ(BCF_EXT_LEN(zext.params), 8);
	EXPECT_EQ(zext.arg0, 99);

	struct bcf_expr_unary sext = BCF_BV_SEXT(16, 8, 77);
	EXPECT_EQ(sext.code, (BCF_BV | BCF_SIGN_EXTEND));
	EXPECT_EQ(sext.vlen, 1);
	EXPECT_EQ(BCF_BV_WIDTH(sext.params), 16);
	EXPECT_EQ(BCF_EXT_LEN(sext.params), 8);
	EXPECT_EQ(sext.arg0, 77);
}

static void test_bv_binop(void)
{
	struct bcf_expr_binary binop = BCF_BV_BINOP(BCF_SDIV, 32, 1, 2);
	EXPECT_EQ(binop.code, (BCF_BV | BCF_SDIV));
	EXPECT_EQ(binop.vlen, 2);
	EXPECT_EQ(BCF_BV_WIDTH(binop.params), 32);
	EXPECT_EQ(binop.arg0, 1);
	EXPECT_EQ(binop.arg1, 2);

	struct bcf_expr_binary alu32 = BCF_ALU32(BCF_SMOD, 3, 4);
	EXPECT_EQ(alu32.code, (BCF_BV | BCF_SMOD));
	EXPECT_EQ(alu32.vlen, 2);
	EXPECT_EQ(BCF_BV_WIDTH(alu32.params), 32);
	EXPECT_EQ(alu32.arg0, 3);
	EXPECT_EQ(alu32.arg1, 4);

	struct bcf_expr_binary alu64 = BCF_ALU64(BCF_SMOD, 5, 6);
	EXPECT_EQ(alu64.code, (BCF_BV | BCF_SMOD));
	EXPECT_EQ(alu64.vlen, 2);
	EXPECT_EQ(BCF_BV_WIDTH(alu64.params), 64);
	EXPECT_EQ(alu64.arg0, 5);
	EXPECT_EQ(alu64.arg1, 6);
}

static void test_bool_var_lit(void)
{
	struct bcf_expr bool_var = BCF_BOOL_VAR;
	EXPECT_EQ(bool_var.code, (BCF_BOOL | BCF_VAR));
	EXPECT_EQ(bool_var.vlen, 0);
	EXPECT_EQ(BCF_BV_WIDTH(bool_var.params), 0);

	struct bcf_expr bool_true = BCF_BOOL_TRUE;
	EXPECT_EQ(bool_true.code, (BCF_BOOL | BCF_VAL));
	EXPECT_EQ(bool_true.vlen, 0);
	EXPECT_EQ(BCF_BOOL_LITERAL(bool_true.params), BCF_TRUE);
	EXPECT_EQ((bool_true.params & ~1), 0);

	struct bcf_expr bool_false = BCF_BOOL_FALSE;
	EXPECT_EQ(bool_false.code, (BCF_BOOL | BCF_VAL));
	EXPECT_EQ(bool_false.vlen, 0);
	EXPECT_EQ(BCF_BOOL_LITERAL(bool_false.params), BCF_FALSE);
	EXPECT_EQ((bool_false.params & ~1), 0);
}

static void test_bool_ops(void)
{
	struct bcf_expr_unary bool_not = BCF_BOOL_NOT(7);
	EXPECT_EQ(bool_not.code, (BCF_BOOL | BCF_NOT));
	EXPECT_EQ(bool_not.vlen, 1);
	EXPECT_EQ(bool_not.params, 0);
	EXPECT_EQ(bool_not.arg0, 7);

	struct bcf_expr_binary bool_and = BCF_BOOL_AND(1, 2);
	EXPECT_EQ(bool_and.code, (BCF_BOOL | BCF_CONJ));
	EXPECT_EQ(bool_and.vlen, 2);
	EXPECT_EQ(bool_and.params, 0);
	EXPECT_EQ(bool_and.arg0, 1);
	EXPECT_EQ(bool_and.arg1, 2);

	struct bcf_expr_binary bool_or = BCF_BOOL_OR(3, 4);
	EXPECT_EQ(bool_or.code, (BCF_BOOL | BCF_DISJ));
	EXPECT_EQ(bool_or.vlen, 2);
	EXPECT_EQ(bool_or.params, 0);
	EXPECT_EQ(bool_or.arg0, 3);
	EXPECT_EQ(bool_or.arg1, 4);

	struct bcf_expr_binary bool_xor = BCF_BOOL_XOR(5, 6);
	EXPECT_EQ(bool_xor.code, (BCF_BOOL | BCF_XOR));
	EXPECT_EQ(bool_xor.vlen, 2);
	EXPECT_EQ(bool_xor.params, 0);
	EXPECT_EQ(bool_xor.arg0, 5);
	EXPECT_EQ(bool_xor.arg1, 6);

	struct bcf_expr_binary bool_implies = BCF_BOOL_IMPLIES(7, 8);
	EXPECT_EQ(bool_implies.code, (BCF_BOOL | BCF_IMPLIES));
	EXPECT_EQ(bool_implies.vlen, 2);
	EXPECT_EQ(bool_implies.params, 0);
	EXPECT_EQ(bool_implies.arg0, 7);
	EXPECT_EQ(bool_implies.arg1, 8);

	struct bcf_expr_binary bool_distinct = BCF_BOOL_DISTINCT(9, 10);
	EXPECT_EQ(bool_distinct.code, (BCF_BOOL | BCF_DISTINCT));
	EXPECT_EQ(bool_distinct.vlen, 2);
	EXPECT_EQ(bool_distinct.params, 0);
	EXPECT_EQ(bool_distinct.arg0, 9);
	EXPECT_EQ(bool_distinct.arg1, 10);

	struct bcf_expr_ternary bool_ite = BCF_BOOL_ITE(1, 2, 3);
	EXPECT_EQ(bool_ite.code, (BCF_BOOL | BCF_ITE));
	EXPECT_EQ(bool_ite.vlen, 3);
	EXPECT_EQ(bool_ite.params, 0);
	EXPECT_EQ(bool_ite.arg0, 1);
	EXPECT_EQ(bool_ite.arg1, 2);
	EXPECT_EQ(bool_ite.arg2, 3);
}

static void test_bool_bitof(void)
{
	struct bcf_expr_unary bool_bitof = BCF_BOOL_BITOF(7, 16, 11);
	EXPECT_EQ(bool_bitof.code, (BCF_BOOL | BCF_BITOF));
	EXPECT_EQ(bool_bitof.vlen, 1);
	EXPECT_EQ(BCF_BITOF_BIT(bool_bitof.params), 7);
	EXPECT_EQ(BCF_BV_WIDTH(bool_bitof.params), 16);
	EXPECT_EQ(bool_bitof.arg0, 11);
}

static struct test_case tests[] = {
	TEST_ENTRY(test_bv_var),     TEST_ENTRY(test_bv_val),
	TEST_ENTRY(test_bv_extract), TEST_ENTRY(test_bv_ext),
	TEST_ENTRY(test_bv_binop),   TEST_ENTRY(test_bool_var_lit),
	TEST_ENTRY(test_bool_ops),   TEST_ENTRY(test_bool_bitof),
};

int main(void)
{
	return run_tests(tests, sizeof(tests) / sizeof(tests[0]),
			 "encoding macro");
}
