// SPDX-License-Identifier: GPL-2.0-only
/* Author: Hao Sun <hao.sun@inf.ethz.ch> */
#include <linux/bpfptr.h>
#include <linux/bcf_checker.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void logger(void *private, const char *fmt, va_list args)
{
	vprintf(fmt, args);
}

static void print_help(void)
{
	u32 total = __MAX_BCF_CORE_RULES + __MAX_BCF_BOOL_RULES +
		    __MAX_BCF_BV_RULES - 3;

	printf("bcf_checker [-v] path/to/proof\n");
	printf("\nAuthor: Hao Sun <hao.sun@inf.ethz.ch>\n");
	printf("Supported rules (%d):\n", total);
	printf("\tcore   : %d\n", __MAX_BCF_CORE_RULES - 1);
	printf("\tboolean: %d\n", __MAX_BCF_BOOL_RULES - 1);
	printf("\tbitvec : %d\n", __MAX_BCF_BV_RULES - 1);
	printf("Supported rewrites: %d\n", __MAX_BCF_REWRITES - 1);
}

int main(int argc, char **argv)
{
	struct stat st;
	void *proof = NULL;
	int fd = -1, ret = 1;
	int level = 1;

	if (argc == 2 && !strcmp(argv[1], "-h")) {
		print_help();
		return 0;
	}

	if (argc > 2 && !strcmp(argv[1], "-v")) {
		level = 2;
		argv++;
		argc--;
	}

	if (argc != 2) {
		fprintf(stderr, "Usage: bcf_checker [-v] <proof_file>\n");
		return 1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		goto out_close;
	}

	proof = malloc(st.st_size);
	if (!proof) {
		perror("malloc");
		goto out_close;
	}

	if (read(fd, proof, st.st_size) != st.st_size) {
		perror("read");
		goto out_free;
	}

	ret = bcf_check_proof(NULL, 0, KERNEL_BPFPTR(proof), st.st_size, logger,
			      level, NULL);
out_free:
	free(proof);
out_close:
	close(fd);
	return ret;
}
