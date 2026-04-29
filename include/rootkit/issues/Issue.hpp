#ifndef ROOTKIT_ISSUES_ISSUE_H
#define ROOTKIT_ISSUES_ISSUE_H

#include "rootkit/issues/Logger.hpp"
#include <string>

namespace rootkit::issues {

class Issue {
protected:
    std::string message;
    const Logger& logger;

    // Make sure that this class is never created from the outside,
    // because it serves as abstract class
    Issue(const Logger& logger);

    virtual ~Issue() = default;

public:
    /**
     * @brief Overload '=' operator, now its assigning new error message,
     * and print it out
     */
    Issue& operator=(const std::string& msg);

    /**
     * @brief Prints out error message
     */
    virtual void print() const;

    /**
     * @brief Returns message
     */
    virtual const std::string& get_message() const;

    virtual bool empty() const;
};

}

#endif
