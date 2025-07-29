#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct trace_event_raw_sys_enter {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
	int __syscall_nr;
	long unsigned int args[6];
	char __data[0];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, unsigned int);
	__type(value, char[4096]);
} map SEC(".maps");

/* https://github.com/llvm/llvm-project/issues/62849 */
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	int key = 0;
	char *buf = (char *)bpf_map_lookup_elem(
		&map, &key); // get ptr of inner buffer
	if (buf == 0)
		return 0;

	char *ptr_name = (char *)ctx->args[0];
	char **argv = (char **)ctx->args[1];
	char *ptr_argv0;
	bpf_probe_read(&ptr_argv0, sizeof(ptr_argv0), argv + 0);

	/* read filename into buffer */
	unsigned int offset = bpf_probe_read_str(buf, 4096, ptr_name);

	/* read argv0 into buffer */
	if (offset > 4096 || offset < 0)
		return 0;
	int len = bpf_probe_read_str(buf + offset, 4096 - offset, ptr_argv0);
	bpf_printk("len : %d\n", len);
	return 0;
}
