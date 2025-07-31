/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LOCKDEP_H
#define _LINUX_LOCKDEP_H

/* Mock lockdep functions for userspace */
static inline int lockdep_is_held(const void *lock)
{
	/* In userspace, assume the lock is always held */
	(void)lock;
	return 1;
}

static inline void lockdep_assert_held(const void *lock)
{
	/* In userspace, no assertion needed */
	(void)lock;
}

static inline void lockdep_assert_not_held(const void *lock)
{
	/* In userspace, no assertion needed */
	(void)lock;
}

/* Additional lockdep macros that might be needed */
#define lockdep_assert_irqs_enabled()	do { } while (0)
#define lockdep_assert_irqs_disabled()	do { } while (0)
#define lockdep_assert_in_irq()		do { } while (0)

#endif /* _LINUX_LOCKDEP_H */
