#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define FILENAME_LEN 256

#define EVENT_EXEC 1
#define EVENT_OPEN 2

struct event {
    __u32 event_type;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    char comm[TASK_COMM_LEN]; //Process name eg curl
    char filename[FILENAME_LEN]; //exec path or openat filename
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); //4 MB
} events SEC(".maps");

static __always_inline __u32 get_ppid(void){
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    __u32 ppid;

    parent = BPF_CORE_READ(task, real_parent);
    ppid = BPF_CORE_READ(parent, tgid);
    return ppid;
}

SEC("tracepoint/sched/sched_process_exe")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx){
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = EVENT_EXEC;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->ppid = get_ppid();
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + (ctx->__data_loc_filename & 0XFFFFFFFF));

    bpf_ringbuf_submit(e,0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx){
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->event_type = EVENT_OPEN;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    e->ppid = get_ppid();
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char *user_filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), user_filename);
    
    bpf_ringbuf_submit(e,0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

//compile -
// clang -O2 target bpf -g -c tracker.bpf.o -o tracker.bpf.o
// bpftool gen skeleton tracker.bpf.o > tracker.skel.h