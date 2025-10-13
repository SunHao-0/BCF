// SPDX-License-Identifier: GPL-2.0-or-later
#ifndef _LINUX_STDARG_H
#define _LINUX_STDARG_H

typedef __builtin_va_list va_list;
#undef  va_start
#define va_start(v, l)	__builtin_va_start(v, l)
#undef va_end 
#define va_end(v)	__builtin_va_end(v)
#undef va_arg
#define va_arg(v, T)	__builtin_va_arg(v, T)
#undef va_copy
#define va_copy(d, s)	__builtin_va_copy(d, s)

#endif
