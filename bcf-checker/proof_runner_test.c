// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpfptr.h>
#include <linux/bcf_checker.h>

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__clang__)
extern int __llvm_profile_set_filename(const char *Filename)
	__attribute__((weak));
extern int __llvm_profile_write_file(void) __attribute__((weak));
#endif

#if defined(__clang__)
static void write_cov_atexit(void)
{
	if (__llvm_profile_write_file)
		(void)__llvm_profile_write_file();
}
#endif

struct result_counter {
	int code;
	unsigned int count;
};

static bool has_ext(const char *name, const char *ext)
{
	size_t ln = strlen(name);
	size_t le = strlen(ext);
	return ln >= le && strcmp(name + (ln - le), ext) == 0;
}

static int add_err(struct result_counter *arr, size_t *len, size_t cap,
		   int code)
{
	for (size_t i = 0; i < *len; i++) {
		if (arr[i].code == code) {
			arr[i].count++;
			return 0;
		}
	}
	if (*len >= cap)
		return -1;
	arr[*len].code = code;
	arr[*len].count = 1;
	(*len)++;
	return 0;
}

static int ensure_dir(const char *path)
{
	struct stat st;
	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode))
			return 0;
		return -1;
	}
	return mkdir(path, 0755);
}

static int process_file(const char *path, int level)
{
	struct stat st;
	void *buf = NULL;
	int fd = -1, ret = -1;

	if (stat(path, &st) < 0)
		return -1;
	if (!S_ISREG(st.st_mode) || st.st_size <= 0)
		return 1; /* skip */
	if (!has_ext(path, ".smt2"))
		return 1; /* skip non-smt2 */
	if ((size_t)st.st_size > MAX_BCF_PROOF_SIZE)
		return -2; /* too big */

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	buf = malloc(st.st_size);
	if (!buf) {
		close(fd);
		return -1;
	}
	ssize_t n = read(fd, buf, st.st_size);
	if (n != st.st_size) {
		free(buf);
		close(fd);
		return -1;
	}

	printf("checking %s (%zu bytes)...\n", path, st.st_size);
	ret = bcf_check_proof(NULL, 0, KERNEL_BPFPTR(buf), (u32)st.st_size,
			      NULL, 0, NULL);

	free(buf);
	close(fd);
	return ret;
}

static int walk_dir(const char *dir, int level, unsigned int *total,
		    unsigned int *ok, unsigned int *fail,
		    struct result_counter *errs, size_t *errs_len,
		    size_t errs_cap)
{
	struct dirent *de;
	char path[4096];
	DIR *dp = opendir(dir);

	if (!dp)
		return -1;

	while ((de = readdir(dp)) != NULL) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		int n = snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
		if (n <= 0 || (size_t)n >= sizeof(path))
			continue;

		if (de->d_type == DT_DIR) {
			/* Recurse */
			walk_dir(path, level, total, ok, fail, errs, errs_len,
				 errs_cap);
			continue;
		}

		int ret = process_file(path, level);
		if (ret == 1)
			continue; /* skipped */
		(*total)++;
		if (ret == 0) {
			(*ok)++;
		} else {
			(*fail)++;
			add_err(errs, errs_len, errs_cap, ret);
		}
	}

	closedir(dp);
	return 0;
}

static bool have_tool(const char *tool)
{
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "command -v %s >/dev/null 2>&1", tool);
	int rc = system(cmd);
	return rc == 0;
}

static void try_print_coverage(const char *self_path)
{
	/* Merge all profile data and show a brief report */
	if (!have_tool("llvm-profdata") || !have_tool("llvm-cov")) {
		fprintf(stderr,
			"coverage tools not found (llvm-profdata/llvm-cov)\n");
		return;
	}

	(void)ensure_dir("build");
	(void)ensure_dir("build/coverage");

#if defined(__clang__)
	/* Force a write of current process counters before scanning */
	if (__llvm_profile_write_file)
		(void)__llvm_profile_write_file();
#endif

	/* Skip merge if no .profraw present */
	DIR *dp = opendir("build/coverage");
	if (!dp) {
		perror("opendir coverage");
		return;
	}
	unsigned int has_profraw = 0;
	struct dirent *de;
	while ((de = readdir(dp)) != NULL) {
		if (strstr(de->d_name, ".profraw")) {
			has_profraw = 1;
			break;
		}
	}
	closedir(dp);
	if (!has_profraw) {
		fprintf(stderr,
			"no .profraw files found; skipping coverage report\n");
		return;
	}

	int rc = system(
		"llvm-profdata merge -sparse build/coverage/*.profraw -o build/coverage/coverage.profdata");
	if (rc != 0) {
		fprintf(stderr, "llvm-profdata merge failed\n");
		return;
	}

	char cmd[8192];
	snprintf(
		cmd, sizeof(cmd),
		"llvm-cov report %s -instr-profile=build/coverage/coverage.profdata"
		" -show-functions=0",
		self_path);
	(void)system(cmd);
}

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [-v] [--cov-report] <proof_dir>\n", prog);
}

int main(int argc, char **argv)
{
	const char *dir = NULL;
	int level = 1;
	bool cov_report = false;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-v")) {
			level = 2;
			continue;
		}
		if (!strcmp(argv[i], "--cov-report")) {
			cov_report = true;
			continue;
		}
		if (argv[i][0] == '-') {
			usage(argv[0]);
			return 1;
		}
		dir = argv[i];
	}

	if (!dir) {
		usage(argv[0]);
		return 1;
	}

	if (cov_report) {
		/* Ensure coverage dir; set runtime filename if available */
		(void)ensure_dir("build");
		(void)ensure_dir("build/coverage");
#if defined(__clang__)
		if (__llvm_profile_set_filename && __llvm_profile_write_file) {
			char prof[256];
			snprintf(prof, sizeof(prof),
				 "build/coverage/proof_runner-%d.profraw",
				 getpid());
			(void)__llvm_profile_set_filename(prof);
			atexit(write_cov_atexit);
		} else
#endif
		{
			if (!getenv("LLVM_PROFILE_FILE"))
				setenv("LLVM_PROFILE_FILE",
				       "build/coverage/proof_runner-%p.profraw",
				       1);
		}
	}

	unsigned int total = 0, ok = 0, fail = 0;
	struct result_counter errs[64];
	size_t errs_len = 0;

	int rc = walk_dir(dir, level, &total, &ok, &fail, errs, &errs_len,
			  ARRAY_SIZE(errs));
	if (rc < 0) {
		perror("opendir");
		return 1;
	}

	printf("\nBCF proof sweep summary:\n");
	printf("  total:   %u\n", total);
	printf("  accept:  %u\n", ok);
	printf("  reject:  %u\n", fail);
	if (fail && errs_len) {
		printf("  error breakdown (ret -> count):\n");
		for (size_t i = 0; i < errs_len; i++)
			printf("    %d -> %u\n", errs[i].code, errs[i].count);
	}

	if (cov_report)
		try_print_coverage(argv[0]);

	return fail ? 1 : 0;
}
