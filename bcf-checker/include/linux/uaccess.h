#ifndef _LINUX_UACCESS_H
#define _LINUX_UACCESS_H

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/bug.h>
#include <string.h>

/*
 * Mocked uaccess.h for userspace/testing.
 * These functions mimic the kernel API but do not perform real user/kernel boundary checks.
 */

static inline int copy_from_user(void *to, const void __user *from, size_t n)
{
	if (!to || !from)
		return n ? -EFAULT : 0;
	memcpy(to, (const void __force *)from, n);
	return 0;
}

static inline int copy_to_user(void __user *to, const void *from, size_t n)
{
	if (!to || !from)
		return n ? -EFAULT : 0;
	memcpy((void __force *)to, from, n);
	return 0;
}

static inline long strncpy_from_user(char *dst, const char __user *src, size_t count)
{
	if (!dst || !src)
		return -EFAULT;
	size_t n = strnlen(src, count - 1);
	if (count == 0)
		return 0;
	size_t len = (n < count - 1) ? n + 1 : count;
	memcpy(dst, (const void __force *)src, len);
	if (len < count)
		dst[len] = '\0';
	return len;
}

static inline int check_zeroed_user(const void __user *src, size_t size)
{
	if (!src)
		return -EFAULT;

	return memchr((const void __force *)src, 0, size) ? 0 : 1;
}

#ifndef clear_user
static inline __must_check unsigned long clear_user(void __user *to,
						    unsigned long n)
{
	memset((void *)to, 0, n);
	return 0;
}
#endif

static __always_inline __must_check int
copy_struct_from_user(void *dst, size_t ksize, const void __user *src,
		      size_t usize)
{
	size_t size = min(ksize, usize);
	size_t rest = max(ksize, usize) - size;

	/* Double check if ksize is larger than a known object size. */
	if (WARN_ON_ONCE(ksize > __builtin_object_size(dst, 1)))
		return -E2BIG;

	/* Deal with trailing bytes. */
	if (usize < ksize) {
		memset(dst + size, 0, rest);
	} else if (usize > ksize) {
		int ret = check_zeroed_user(src + size, rest);
		if (ret <= 0)
			return ret ?: -E2BIG;
	}
	/* Copy the interoperable parts of the struct. */
	if (copy_from_user(dst, src, size))
		return -EFAULT;
	return 0;
}

#ifndef memchr_inv
static inline void *memchr_inv(const void *start, int c, size_t size)
{
	const unsigned char *p = (const unsigned char *)start;
	while (size--) {
		if (p[size] != (unsigned char)c)
			return (void *)&p[size];
	}
	return NULL;
}
#endif

static __always_inline __must_check int
copy_struct_to_user(void __user *dst, size_t usize, const void *src,
		    size_t ksize, bool *ignored_trailing)
{
	size_t size = min(ksize, usize);
	size_t rest = max(ksize, usize) - size;

	/* Double check if ksize is larger than a known object size. */
	if (WARN_ON_ONCE(ksize > __builtin_object_size(src, 1)))
		return -E2BIG;

	/* Deal with trailing bytes. */
	if (usize > ksize) {
		if (clear_user(dst + size, rest))
			return -EFAULT;
	}
	if (ignored_trailing)
		*ignored_trailing = ksize < usize &&
				    memchr_inv(src + size, 0, rest) != NULL;
	/* Copy the interoperable parts of the struct. */
	if (copy_to_user(dst, src, size))
		return -EFAULT;
	return 0;
}

#define u64_to_user_ptr(p) ((void __user *)(u64)(p))

static inline int copy_from_kernel_nofault(void *dst, const void *src, size_t size)
{
	memcpy(dst, src, size);
	return 0;
}

#endif /* _LINUX_UACCESS_H */
