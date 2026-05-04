#ifndef ROOTKIT_ARG_MANAGER_H
#define ROOTKIT_ARG_MANAGER_H

#include <string>

namespace rootkit {

struct Args {
    bool run = false;
    bool install = false;
    bool help = false;
    std::string cwd = "";
};

class ArgManager {
private:
    Args args;
public:
    /**
     * @brief Read and process args that were passed to main function
     * @param argc Number parameters
     * @param argv C-style array of strings
     */
    ArgManager(int argc, char ** argv);

    /**
     * @brief Return processed args
     */
    const Args& getArgs() const;

    /**
     * @brief Print out manual for arguments for this program
     */
    void help() const;
};

}

#endif
