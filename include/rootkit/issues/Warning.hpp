#ifndef ROOTKIT_ISSUES_WARNING_H
#define ROOTKIT_ISSUES_WARNING_H

#include "Issue.hpp"

namespace rootkit::issues {

class Warning : public Issue {
public:
    using Issue::Issue;

    using Issue::operator=;

    Warning(const Logger& logger);

    /**
     * @brief Prints out warning message
     */
    void print() const override;
};

}

#endif
