

CC := clang-18
CFLAGS := -Wall -Werror -g -O2 -target bpf
CFLAGS += -Wno-compare-distinct-pointer-types
CFLAGS += -I/local/home/sunhao/kernels/linux-stable/usr/include

BPF_PROGS = system_monitor trace_sys_enter_execve shift_constraint	\
		 unreachable_arsh test_get_stack_rawtp stack_ptr_varoff ksnoop	\
		 xdp_synproxy_kern tcp_conn_tuner scx_util

BPF_OBJS = $(BPF_PROGS:%=%.bpf.o)

all: $(BPF_OBJS)

%.bpf.o: %.bpf.c
	$(CC) $(CFLAGS) -c $< -o $@

format:
	clang-format -i *.c

clean:
	rm -f *.o
