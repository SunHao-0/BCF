#ifndef __LINUX_PRINTK_H__
#define __LINUX_PRINTK_H__

#include <stdio.h>

#define KERN_EMERG "EMERG"
#define KERN_ALERT "ALERT"
#define KERN_CRIT "CRIT"
#define KERN_ERR "ERR"
#define KERN_WARNING "WARNING"
#define KERN_NOTICE "NOTICE"
#define KERN_INFO "INFO"
#define KERN_DEBUG "DEBUG"

#define pr_info(fmt, ...) printf(fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...) printf(fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...) printf(fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...) printf(fmt, ##__VA_ARGS__)
#define printk(level, fmt, ...) printf("[%s]: " fmt, level, ##__VA_ARGS__)

#endif // __LINUX_PRINTK_H__