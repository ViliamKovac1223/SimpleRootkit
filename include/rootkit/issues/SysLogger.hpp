#ifndef ROOTKIT_ISSUES_SYS_LOGGER_H
#define ROOTKIT_ISSUES_SYS_LOGGER_H

#include "Logger.hpp"

namespace rootkit::issues {

class SysLogger : public Logger {
private:
    std::string prefix;
public:
    /**
     * @brief Construct sysloger
     */
    SysLogger();

    /**
     * @brief Syslog out error message
     */
    virtual void print_error(const std::string& message) const override;

    /**
     * @brief Syslog out warning message
     */
    virtual void print_warning(const std::string& message) const override;

    /**
     * @brief Syslog out info message
     */
    virtual void print_info(const std::string& message) const override;
};

}

#endif
