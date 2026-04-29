#include "rootkit/issues/Issue.hpp"

namespace rootkit::issues {

Issue::Issue(const Logger& logger) :logger(logger) {}

void Issue::print() const {
    logger.print_info(message);
}

const std::string& Issue::get_message() const {
    return message;
}

Issue& Issue::operator=(const std::string& msg) {
    message = msg;
    print();
    return *this;
}


bool Issue::empty() const {
    return message.empty();
}

}
