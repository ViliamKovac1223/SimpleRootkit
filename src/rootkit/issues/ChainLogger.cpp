#include "rootkit/issues/ChainLogger.hpp"

using namespace rootkit::issues;

ChainLogger::ChainLogger(std::vector<std::unique_ptr<Logger>> loggers)
    :loggers(std::move(loggers))
{
}

void ChainLogger::print_error(const std::string& message) const {
    for (auto& logger : loggers)
        logger->print_error(message);
}

void ChainLogger::print_warning(const std::string& message) const {
    for (auto& logger : loggers)
        logger->print_warning(message);
}

void ChainLogger::print_info(const std::string& message) const {
    for (auto& logger : loggers)
        logger->print_info(message);
}
