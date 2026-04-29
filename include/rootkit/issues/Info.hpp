#ifndef ROOTKIT_ISSUES_INFO_H
#define ROOTKIT_ISSUES_INFO_H

#include "Issue.hpp"

namespace rootkit::issues {

class Info : public Issue {
public:
    using Issue::Issue;

    using Issue::operator=;

    Info(const Logger& logger);

    /**
     * @brief Prints out info message
     */
    void print() const override;
};

}

#endif
