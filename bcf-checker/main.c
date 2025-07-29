// SPDX-License-Identifier: GPL-2.0-only
/* Author: Hao Sun <hao.sun@inf.ethz.ch> */
#include <linux/bpfptr.h>
#include <linux/bcf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	struct bpf_verifier_env env = {};
	union bpf_attr attr = {};
	bpfptr_t uattr;
	struct stat st;
	void *proof = NULL;
	int fd = -1, ret = 1;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <proof_file>\n", argv[0]);
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

	attr.bcf_buf = (u64)(uintptr_t)proof;
	attr.bcf_buf_size = st.st_size;
	attr.bcf_buf_true_size = st.st_size;
	uattr = USER_BPFPTR(&attr);

	(void)bcf_check_proof(&env, &attr, uattr);

	ret = 0;

out_free:
	free(proof);
out_close:
	close(fd);
	return ret;
}
