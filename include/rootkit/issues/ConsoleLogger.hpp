#ifndef ROOTKIT_ISSUES_CONSOLE_LOGGER_H
#define ROOTKIT_ISSUES_CONSOLE_LOGGER_H

#include "Logger.hpp"

namespace rootkit::issues {

class ConsoleLogger : public Logger {
public:
    /**
     * @brief Prints out error message
     */
    virtual void print_error(const std::string& message) const override;

    /**
     * @brief Prints out warning message
     */
    virtual void print_warning(const std::string& message) const override;

    /**
     * @brief Prints out info message
     */
    virtual void print_info(const std::string& message) const override;
};

}

#endif
