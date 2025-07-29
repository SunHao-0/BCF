/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LIBLOCKDEP_RCU_H_
#define _LIBLOCKDEP_RCU_H_

#include <linux/types.h>
#include <linux/compiler.h>

// int rcu_scheduler_active;

static inline int rcu_lockdep_current_cpu_online(void)
{
	return 1;
}

static inline int rcu_is_cpu_idle(void)
{
	return 1;
}

static inline bool rcu_is_watching(void)
{
	return false;
}

#define rcu_assign_pointer(p, v)	do { (p) = (v); } while (0)
#define RCU_INIT_POINTER(p, v)	do { (p) = (v); } while (0)

/* Additional RCU functions needed by xarray.h */
#define rcu_dereference_check(p, c)	(p)
#define rcu_dereference_protected(p, c)	(p)

/* RCU head structure for xarray nodes */
struct rcu_head {
	void (*func)(struct rcu_head *head);
	struct rcu_head *next;
	int state;
};

/* RCU callback functions */
static inline void call_rcu(struct rcu_head *head, void (*func)(struct rcu_head *head))
{
	/* In userspace, just call the function immediately */
	if (func)
		func(head);
}

static inline void synchronize_rcu(void)
{
	/* In userspace, no synchronization needed */
}

static inline void rcu_read_lock(void)
{
	/* In userspace, no locking needed */
}

static inline void rcu_read_unlock(void)
{
	/* In userspace, no unlocking needed */
}

#define __rcu_dereference_raw(p) \
({ \
	((typeof(*p) __force *)(p)); \
})
#define rcu_dereference_raw(p) __rcu_dereference_raw(p)

#endif
