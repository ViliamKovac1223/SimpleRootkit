#include "rootkit/KernelModuleHelper.hpp"

#include <fcntl.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <cstdint>
#include <format>

rootkit::KernelModuleHelper::KernelModuleHelper(const std::string& module_path,
                        const std::string& module_name,
                        const std::string& module_dev_name
)
    :module_name(module_name),
    module_path(module_path),
    module_dev_name(module_dev_name),
    loading_error(""),
    data(std::nullopt)
{
    int fd = open(module_path.c_str(), O_RDONLY);
    if (fd < 0) {
        loading_error = "file " + module_path + " cannot be read";
        std::cerr << loading_error << std::endl;
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
        // Get error message into the loading_error variable
        const char * msg = std::strerror(saved_errno);
        if (msg && *msg)
            loading_error = std::format("init_module: {}", msg);

        // Check if the error is permission or module state
        if (saved_errno == EPERM) {
            loading_error += "\nPermission denied - check SELinux status, secure boot, or capabilities";
        } else if (saved_errno == EEXIST) {
            loading_error += "\nModule already loaded";
        } else if (saved_errno == ENOEXEC) {
            loading_error += "\nModule format error";
        }
        std::cerr << loading_error << std::endl;
    }
}

rootkit::KernelModuleHelper::~KernelModuleHelper() {
    // Check for error in loading, and if any don't unload the kernel module
    if (!loading_error.empty())
        return;
    // Unload module
    if (delete_module(module_name.c_str(), O_NONBLOCK) < 0) {
        perror("Error unloading module");
    }
}

std::optional<std::string> rootkit::KernelModuleHelper::status() const {
    if (!loading_error.empty())
        return loading_error;
    return std::nullopt;
}

bool rootkit::KernelModuleHelper::setData(const conn_info& data) {
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
    this->data = data;

    return true;
}

std::optional<conn_info> rootkit::KernelModuleHelper::getData() {
    return data;
}
