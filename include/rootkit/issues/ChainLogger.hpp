#ifndef ROOTKIT_ISSUES_CHAIN_LOGGER_H
#define ROOTKIT_ISSUES_CHAIN_LOGGER_H

#include "Logger.hpp"
#include <memory>
#include <vector>

namespace rootkit::issues {

class ChainLogger : public Logger {
private:
    std::vector<std::unique_ptr<Logger>> loggers;

public:

    /**
     * @brief Construct chain of loggers
     */
    ChainLogger(std::vector<std::unique_ptr<Logger>> loggers);

    /**
     * @brief Logs out error message
     */
    virtual void print_error(const std::string& message) const override;

    /**
     * @brief Logs out warning message
     */
    virtual void print_warning(const std::string& message) const override;

    /**
     * @brief Logs out info message
     */
    virtual void print_info(const std::string& message) const override;
};

}

#endif
