#include "rootkit/Utils.hpp"
#include <sys/stat.h>
#include <unistd.h>

namespace rootkit::utils {

std::optional<__u32> convert_ip(const std::string& ip) {
    __u32 ip_address;
    if (inet_pton(AF_INET, "192.168.70.165", &ip_address) <= 0) {
        perror("inet_pton failed");
        return std::nullopt;
    }

    return ip_address;
}

std::optional<uint64_t> get_inode_of_process(const pid_t pid) {
    struct stat sb;
    std::string proc_path = "/proc/" + std::to_string(pid);

    if (stat(proc_path.c_str(), &sb) < 0) {
        perror("stat failed");
        return std::nullopt;
    }

    return static_cast<uint64_t>(sb.st_ino);
}

std::optional<uint64_t> get_inode_of_file(const std::string& file_path) {
    struct stat sb;

    if (stat(file_path.c_str(), &sb) < 0) {
        perror("stat failed");
        return std::nullopt;
    }

    return static_cast<uint64_t>(sb.st_ino);
}

std::string get_cwd() {
    char cwd[256];
    getcwd(cwd, sizeof(cwd));

    return cwd;
}

}
