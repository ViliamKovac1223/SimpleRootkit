#ifndef ROOTKIT_UTILS_H
#define ROOTKIT_UTILS_H

#include <optional>
#include <asm-generic/int-ll64.h>
#include <string>
#include <arpa/inet.h>

namespace rootkit::utils {
    std::optional<__u32> convert_ip(const std::string& ip);
}

#endif
