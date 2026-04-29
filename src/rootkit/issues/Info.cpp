#include "rootkit/issues/Info.hpp"

namespace rootkit::issues {

Info::Info(const Logger& logger) :Issue(logger) {}

void Info::print() const {
    logger.print_info(message);
}

}
