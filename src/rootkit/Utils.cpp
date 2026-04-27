#include "rootkit/Utils.hpp"

namespace rootkit::utils {

std::optional<__u32> convert_ip(const std::string& ip) {
    __u32 ip_address;
    if (inet_pton(AF_INET, "192.168.70.165", &ip_address) <= 0) {
        perror("inet_pton failed");
        return std::nullopt;
    }

    return ip_address;
}

}
