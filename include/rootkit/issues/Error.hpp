#ifndef ROOTKIT_ISSUES_ERROR_H
#define ROOTKIT_ISSUES_ERROR_H

#include "Issue.hpp"

namespace rootkit::issues {

class Error : public Issue {
public:
    using Issue::Issue;

    using Issue::operator=;

    Error(const Logger& logger);

    /**
     * @brief Prints out error message
     */
    void print() const override;
};

}

#endif
