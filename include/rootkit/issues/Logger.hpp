#ifndef ROOTKIT_ISSUES_LOGGER_H
#define ROOTKIT_ISSUES_LOGGER_H

#include <string>

namespace rootkit::issues {

class Logger {
public:
    virtual ~Logger() = default;

    /**
     * @brief Prints out error message
     */
    virtual void print_error(const std::string& message) const = 0;

    /**
     * @brief Prints out warning message
     */
    virtual void print_warning(const std::string& message) const = 0;

    /**
     * @brief Prints out info message
     */
    virtual void print_info(const std::string& message) const = 0;
};

}

#endif
