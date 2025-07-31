#ifndef __LINUX_BPF_VERIFIER_H__
#define __LINUX_BPF_VERIFIER_H__

#include <linux/types.h>
#include <uapi/linux/bcf.h>

struct bcf_state {
	struct bcf_expr *exprs;
	u32 goal;
};

struct bpf_verifier_env {
	struct bcf_state bcf;
	u32 todo;
};

#endif /* __LINUX_BPF_VERIFIER_H__ */
