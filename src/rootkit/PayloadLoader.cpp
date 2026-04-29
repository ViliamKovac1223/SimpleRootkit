#include "rootkit/PayloadLoader.hpp"
#include "rootkit/ConfigManager.hpp"
#include "rootkit/issues/Warning.hpp"

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <optional>
#include <sys/wait.h>
#include <unistd.h>

rootkit::PayloadLoader::PayloadLoader(const PayloadConfig& conf,
        const issues::Logger& logger)
    :payload_path(conf.path),
    info(logger),
    warning(logger),
    error(logger)
{}

rootkit::PayloadLoader::~PayloadLoader() {
    if (!is_running()) return;

    // Try to gracefully stop the payload, if it doesn't work kill the payload
    if (stop() == false) {
        kill();
    }
}

bool rootkit::PayloadLoader::start() {
    auto ret = fork();

    if (ret == 0) { // New process
        char * args[] = {(char *) payload_path.c_str(), nullptr};
        execve(payload_path.c_str(), args, environ);
    } else if (ret == -1) { // Error
        error = "Couldn't execute payload";
        return false;
    }
    // Continue
    this->pid = ret;

    return true;
}

bool rootkit::PayloadLoader::is_running() {
    if (pid == 0)
        return false;

    // Check if process is running
    pid_t result = waitpid(pid, nullptr, WNOHANG);
    if (result == -1) return false; // Process doesn't exist
    if (result == pid) return false; // Process has exited
    if (result == 0) return true; // Process is running

    return false;
}

std::optional<pid_t> rootkit::PayloadLoader::get_pid() {
    if (!is_running()) return std::nullopt;
    return pid;
}

bool rootkit::PayloadLoader::stop() {
    if (!is_running()) return true;

    ::kill(pid, SIGTERM);

    auto startTime = std::chrono::steady_clock::now();

    while (true) {
        int status;

        // Check if the process is still running
        if (!is_running()) {
            pid = 0; // Reset pid
            return true;
        }

        auto elapsed = std::chrono::steady_clock::now() - startTime;
        if (std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()
            >= KILL_MAX_WAITING_TIME_IN_MS) { // Timeout
                warning = std::format("Couldn't stop payload (pid: {}) with stop method", pid);
                return false;
        }

        // Wait before next attempt
        usleep(KILL_WAITING_TIME_IN_MS * 1000);
    }

    return false;
}

void rootkit::PayloadLoader::kill() {
    if (!is_running()) return;
    ::kill(pid, SIGKILL);
    pid = 0; // Reset pid
}
