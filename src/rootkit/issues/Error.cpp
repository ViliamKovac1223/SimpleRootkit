#include "rootkit/issues/Error.hpp"

namespace rootkit::issues {


Error::Error(const Logger& logger) :Issue(logger) {}

void Error::print() const {
    logger.print_error(message);
}

}
