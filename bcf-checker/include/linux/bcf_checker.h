/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __LINUX_BCF_CHECKER_H__
#define __LINUX_BCF_CHECKER_H__

#include <uapi/linux/bcf.h>
#include <linux/stdarg.h>
#include <linux/bpfptr.h>
#include <linux/bpf_verifier.h> /* For log level. */

#define MAX_BCF_PROOF_SIZE (8 * 1024 * 1024)

typedef void (*bcf_logger_t)(void *private, const char *fmt, va_list args);

int bcf_check_proof(struct bcf_expr *goal_exprs, u32 goal, bpfptr_t proof,
		    u32 proof_size, bcf_logger_t logger, u32 level,
		    void *private);

#endif /* __LINUX_BCF_CHECKER_H__ */
