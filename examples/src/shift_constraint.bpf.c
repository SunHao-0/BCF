// SPDX-License-Identifier: GPL-2.0
/* Converted from tools/testing/selftests/bpf/verifier/and.c */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct trace_event_raw_sys_enter {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
	int __syscall_nr;
	long unsigned int args[6];
	char __data[0];
};

SEC("tracepoint/syscalls/sys_enter_execve")
int shift_constraint(struct trace_event_raw_sys_enter *ctx)
{
	/* https://lpc.events/event/18/contributions/1939/
	 * example (2)
	 */
	asm volatile("call 0x7\n\t"
		     "w0 = w0\n\t"
		     "w0 &= 0xff\n\t"
		     "w1 = w0\n\t"
		     "r2 = r10\n\t"
		     "r2 += -16\n\t"
		     "r2 += r0\n\t"
		     "r1 >>= 1\n\t"
		     "if r1 > 4 goto +1\n\t"
		     "r0 = *(u8*)(r2 + 0)\n\t");

	return 0;
}
char _license[] SEC("license") = "GPL";
