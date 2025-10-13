#ifndef __LINUX_BPF_VERIFIER_H__
#define __LINUX_BPF_VERIFIER_H__

#include <linux/types.h>
#include <linux/bpf.h>
#include <uapi/linux/bcf.h>

struct bcf_state {
	struct bcf_expr *exprs;
	u32 goal;
};

#define BPF_LOG_LEVEL1 1
#define BPF_LOG_LEVEL2 2
#define BPF_LOG_STATS 4
#define BPF_LOG_FIXED 8
#define BPF_LOG_LEVEL (BPF_LOG_LEVEL1 | BPF_LOG_LEVEL2)
#define BPF_LOG_MASK (BPF_LOG_LEVEL | BPF_LOG_STATS | BPF_LOG_FIXED)
#define BPF_LOG_KERNEL (BPF_LOG_MASK + 1) /* kernel internal flag */
#define BPF_LOG_MIN_ALIGNMENT 8U
#define BPF_LOG_ALIGNMENT 40U

struct bpf_verifier_env {
	struct bcf_state bcf;
	u32 todo;
};

#endif /* __LINUX_BPF_VERIFIER_H__ */
