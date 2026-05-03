#include "rootkit/issues/SysLogger.hpp"

#include <format>
#include <sys/syslog.h>

using namespace rootkit::issues;

SysLogger::SysLogger()
    :prefix("Rootkit")
{}

void SysLogger::print_error(const std::string& message) const {
    if (!message.empty()) {
        syslog(LOG_ERR, "%s\n", std::format("{}: [ERROR] {}", prefix, message).c_str());
    }
}

void SysLogger::print_warning(const std::string& message) const {
    if (!message.empty()) {
        syslog(LOG_WARNING, "%s\n", std::format("{}: [WARNING] {}", prefix, message).c_str());
    }
}

void SysLogger::print_info(const std::string& message) const {
    if (!message.empty()) {
        syslog(LOG_INFO, "%s\n", std::format("{}: [INFO] {}", prefix, message).c_str());
    }
}
