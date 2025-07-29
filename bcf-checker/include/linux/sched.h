#ifndef _LINUX_SCHED_H
#define _LINUX_SCHED_H

#include <asm/current.h>
#include <linux/types.h>

struct task_struct {
	u32 pid;
	/* dummy */
};

static bool need_resched(void)
{
	return false;
}

static int cond_resched(void)
{
	return 0;
}

#endif /* _LINUX_SCHED_H */

