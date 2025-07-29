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
	 * example (1) extended with multiple paths
	 */
	asm volatile("call 0x7\n\t"
		     "w0 &= 0xf\n\t"
		     "r1 = r10\n\t"
		     "r1 += -16\n\t"
		     "r1 += r0\n\t"
		     "r2 = 0xf\n\t"
		     "r2 -= r0\n\t"
		     "if r2 < 0x4 goto +3\n\t"
		     "r1 += 4\n\t"
		     "r0 = *(u8*)(r1 + 0)\n\t"
		     "exit\n\t"
		     "r1 += r2\n\t"
		     "r0 = *(u8*)(r1 + 0)\n\t");

	return 0;
}
char _license[] SEC("license") = "GPL";
