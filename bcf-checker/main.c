// SPDX-License-Identifier: GPL-2.0-only
/* Author: Hao Sun <hao.sun@inf.ethz.ch> */
#include <linux/bpfptr.h>
#include <linux/bcf_checker.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <linux/slab.h>

static void logger(void *private, const char *fmt, va_list args)
{
	vprintf(fmt, args);
}

static void print_help(void)
{
	u32 total = __MAX_BCF_CORE_RULES + __MAX_BCF_BOOL_RULES +
		    __MAX_BCF_BV_RULES - 3;

	printf("bcf_checker [-v] [-b] path/to/proof\n");
	printf("\nAuthor: Hao Sun <hao.sun@inf.ethz.ch>\n");
	printf("Supported rules (%d):\n", total);
	printf("\tcore   : %d\n", __MAX_BCF_CORE_RULES - 1);
	printf("\tboolean: %d\n", __MAX_BCF_BOOL_RULES - 1);
	printf("\tbitvec : %d\n", __MAX_BCF_BV_RULES - 1);
	printf("Supported rewrites: %d\n", __MAX_BCF_REWRITES - 1);
}

void *read_file(char *path, u32 *size)
{
	char err[128];
	struct stat st;
	void *ret = NULL;
	int fd;

	fd = open(path, O_RDONLY);
	snprintf(err, 128, "failed to open %s", path);
	if (fd < 0)
		goto out;

	if (fstat(fd, &st) < 0)
		goto out;
	*size = st.st_size;

	ret = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd,
		   0);
	if (ret == MAP_FAILED)
		ret = NULL;
out:
	if (fd >= 0)
		close(fd);
	if (!ret)
		perror(err);
	return ret;
}

#define EXPR_SZ(expr) ((expr)->vlen + 1)

static bool expr_arg_is_id(u8 code)
{
	return code != (BCF_BV | BCF_VAL);
}

/* `goal_exprs` is an array of bcf_expr, and `goal` is the index to the top
 * level expr. This expr buf produced by the verifier may contain unused exprs,
 * e.g., [0: var0, 1: var1, 2: extract 0, 3: extract 1, 4: add 3 3], in this
 * expr buf, suppose 4 is the goal idx, then `0` and `2` are unused exprs,
 * since `4` refers to `3` and `3` refers to `1`. This can heppen since the
 * exprs may be just some intermediate exprs not refered by the goal.
 *
 * `compact_goal()` walks the goal and preserves only used exprs and eliminate
 * unused ones, it also 'fix' the idx. Every expr in the buf only refers to
 * the exprs before it; this should hold before and after this compaction.
 * This should eventually be added to the verifier.
 */
struct bcf_iter_state {
	u32 idx;
	u32 cur_arg;
};

#define BCF_MAX_STACK 64

int compact_goal(struct bcf_expr *goal_exprs, u32 *goal)
{
	struct bcf_iter_state stack[BCF_MAX_STACK];
	u32 *map;
	u32 size, dst, src;
	u32 sp = 0;
	u32 goal_idx = *goal;
	struct bcf_expr *root;

	root = goal_exprs + goal_idx;
	size = goal_idx + EXPR_SZ(root);

	/* Map stores the new index for each old index. */
	map = calloc(size, sizeof(u32));
	if (!map)
		return -ENOMEM;
	memset(map, 0xFF, size * sizeof(u32));

	/* Marking phase: DFS from goal */
	stack[sp++] = (struct bcf_iter_state){ .idx = goal_idx, .cur_arg = 0 };
	map[goal_idx] = 1; /* Mark as visited */

	while (sp > 0) {
		struct bcf_iter_state *top = &stack[sp - 1];
		struct bcf_expr *expr = goal_exprs + top->idx;

		if (!expr_arg_is_id(expr->code)) {
			sp--;
			continue;
		}

		if (top->cur_arg >= expr->vlen) {
			sp--;
			continue;
		}

		u32 arg_idx = expr->args[top->cur_arg++];
		if (arg_idx >= size)
			continue;

		if (map[arg_idx] == U32_MAX) {
			if (sp >= BCF_MAX_STACK) {
				free(map);
				return -E2BIG;
			}
			map[arg_idx] = 1; /* Mark visited */
			stack[sp++] = (struct bcf_iter_state){ .idx = arg_idx,
							       .cur_arg = 0 };
		}
	}

	/* Compaction phase: linear scan */
	dst = 0;
	src = 0;
	while (src < size) {
		struct bcf_expr *src_expr = goal_exprs + src;
		u32 sz = EXPR_SZ(src_expr);

		/* If visited/marked */
		if (map[src] != U32_MAX) {
			struct bcf_expr *dst_expr = goal_exprs + dst;

			/* Record new location */
			map[src] = dst;

			/* Move expression */
			if (dst != src) {
				*dst_expr = *src_expr;
				memcpy(dst_expr->args, src_expr->args,
				       src_expr->vlen * sizeof(u32));
			}

			/* Remap arguments */
			if (expr_arg_is_id(dst_expr->code)) {
				u32 i;
				for (i = 0; i < dst_expr->vlen; i++) {
					u32 old_arg = dst_expr->args[i];
					/* map[old_arg] is valid because old_arg < src
					 * and must have been visited/compacted.
					 */
					dst_expr->args[i] = map[old_arg];
				}
			}

			dst += sz;
		}

		src += sz;
	}

	*goal = map[goal_idx];
	free(map);
	return dst;
}

int main(int argc, char **argv)
{
	u32 *proof, *goal_exprs = NULL;
	u32 proof_sz, goal_sz, goal = 0;
	int ret = 1, level = 1;
	bool benchmark = false;
	struct timespec start, end;

	if (argc == 2 && !strcmp(argv[1], "-h")) {
		print_help();
		return 0;
	}

	while (argc > 1) {
		if (!strcmp(argv[1], "-v")) {
			level = 2;
			argv++;
			argc--;
			continue;
		}
		if (!strcmp(argv[1], "-b")) {
			benchmark = true;
			argv++;
			argc--;
			continue;
		}
		break;
	}

	if (argc != 2 && argc != 3) {
		fprintf(stderr,
			"Usage: bcf_checker [-v] [-b] [goal] <proof_file>\n");
		return 1;
	}

	if (argc == 3) {
		goal_exprs = read_file(argv[1], &goal_sz);
		if (!goal_exprs)
			return 1;
		/* The first u32 is the goal idx. */
		goal = *goal_exprs;
		goal_exprs++;
		if (compact_goal((struct bcf_expr *)goal_exprs, &goal) < 0) {
			fprintf(stderr, "Failed to compact goal\n");
			return 1;
		}
		argv++;
		argc--;
	}

	proof = read_file(argv[1], &proof_sz);
	if (!proof)
		goto out;

	if (benchmark)
		clock_gettime(CLOCK_MONOTONIC, &start);

	ret = bcf_check_proof((void *)goal_exprs, goal, KERNEL_BPFPTR(proof),
			      proof_sz, logger, level, NULL);

	if (benchmark) {
		u64 time_us;
		long mem_bytes;

		clock_gettime(CLOCK_MONOTONIC, &end);
		mem_bytes = atomic_load(&kmalloc_max_bytes_allocated);
		time_us = (end.tv_sec - start.tv_sec) * 1000000ULL +
			  (end.tv_nsec - start.tv_nsec) / 1000;
		printf("{\"time_us\": %lu, \"memory_bytes\": %ld, \"status\": %d}\n",
		       time_us, mem_bytes, ret);
	}

out:
	if (goal_exprs)
		munmap(goal_exprs, goal_sz);
	if (proof)
		munmap(proof, proof_sz);
	return ret;
}
