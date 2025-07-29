#ifndef _LINUX_SCHED_SIGNAL_H
#define _LINUX_SCHED_SIGNAL_H

#include <linux/sched.h>

static inline int signal_pending(struct task_struct *p)
{
	(void)p;
	return 0;
}

#endif /* _LINUX_SCHED_SIGNAL_H */

