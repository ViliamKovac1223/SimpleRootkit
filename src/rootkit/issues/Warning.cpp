#include "rootkit/issues/Warning.hpp"

namespace rootkit::issues {

Warning::Warning(const Logger& logger) :Issue(logger) {}

void Warning::print() const {
    logger.print_warning(message);
}

}
