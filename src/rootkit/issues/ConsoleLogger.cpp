#include "rootkit/issues/ConsoleLogger.hpp"

#include <iostream>

using namespace rootkit::issues;

void ConsoleLogger::print_error(const std::string& message) const {
    if (!message.empty()) {
        std::cerr << "[ERROR] " << message << std::endl;
    }
}

void ConsoleLogger::print_warning(const std::string& message) const {
    if (!message.empty()) {
        std::cout << "[WARNING] " << message << std::endl;
    }
}

void ConsoleLogger::print_info(const std::string& message) const {
    if (!message.empty()) {
        std::cout << "[INFO] " << message << std::endl;
    }
}
