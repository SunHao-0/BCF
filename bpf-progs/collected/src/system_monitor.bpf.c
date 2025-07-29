#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef __u32 u32;

#define S32_MAX 0x7fffffff

typedef __u8 u8;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_BUFFER_SIZE 4096
#define MAX_STRING_SIZE 1024

typedef struct buffers {
	unsigned char buf[MAX_BUFFER_SIZE];
} bufs_t;

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, unsigned int);
	__type(value, bufs_t);
} bufs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 4);
	__type(key, unsigned int);
	__type(value, u32);
} bufs_offset SEC(".maps");

static __always_inline u32 *get_buffer_offset(int buf_type)
{
	return bpf_map_lookup_elem(&bufs_offset, &buf_type);
}

/* simplified version of https://github.com/kubearmor/KubeArmor/blob/31c0977b6c63743b7a8268a2922875f9b9051820/KubeArmor/BPF/system_monitor.c#L612*/
static __always_inline int save_str_to_buffer(bufs_t *bufs_p, void *ptr)
{
	u32 *off = get_buffer_offset(0);
	if (off == NULL) {
		return -1;
	}

	if (*off >= MAX_BUFFER_SIZE) {
		return 0;
	}

	u32 type_pos = *off;
	if (type_pos + 1 > MAX_BUFFER_SIZE) {
		return 0;
	}

	if (MAX_BUFFER_SIZE - type_pos < (1 + sizeof(int) + 1)) {
		return 0;
	}

	u32 size_pos = type_pos + 1;
	u32 str_pos = size_pos + sizeof(int);

	u32 read_size = (MAX_BUFFER_SIZE - str_pos);
	int sz = bpf_probe_read_str(&(bufs_p->buf[str_pos]), read_size, ptr);
	if (sz <= 0) {
		return 0;
	}

	if (bpf_probe_read(&(bufs_p->buf[size_pos]), sizeof(int), &sz) < 0) {
		return 0;
	}

	return sz + sizeof(int);
}

static __always_inline bufs_t *get_buffer(int buf_type)
{
	return bpf_map_lookup_elem(&bufs, &buf_type);
}

SEC("kprobe/security_bprm_check")
int kprobe__security_bprm_check(struct pt_regs *ctx)
{
	bufs_t *bufs_p = get_buffer(1);
	if (bufs_p == NULL)
		return 0;

	bufs_t *string_p = get_buffer(0);
	if (string_p == NULL)
		return -1;

	save_str_to_buffer(bufs_p, (void *)&string_p->buf[0]);
	return 0;
}
