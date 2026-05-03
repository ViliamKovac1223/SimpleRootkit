#include "rootkit/ArgManager.hpp"

#include <iostream>
#include <getopt.h>
#include <string>

enum {
    OPT_RUN,
    OPT_INSTALL,
    OPT_HELP,
    OPT_CWD
};

rootkit::ArgManager::ArgManager(int argc, char ** argv) {
    const char* cwd = nullptr;

    static struct option long_options[] = {
        {"run",     no_argument,       nullptr, OPT_RUN},
        {"install", no_argument,       nullptr, OPT_INSTALL},
        {"help",    required_argument, nullptr, OPT_HELP},
        {"cwd",     required_argument, nullptr, OPT_CWD},
        {nullptr,   0,                 nullptr, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "", long_options, nullptr)) != -1) {
        switch (opt) {
            case OPT_RUN:
                args.run = true;
                break;
            case OPT_INSTALL:
                args.install = true;
                break;
            case OPT_HELP:
                args.help = true;
                break;
            case OPT_CWD:
                // Safe conversion of optarg (char *) to std::string
                args.cwd =  optarg ? std::string(optarg) : std::string("");
                break;
            case '?':
                std::cerr << "Invalid option\n";
                help();
                exit(1);
        }
    }

    // If run and install options are both true, select only installing.
    // Program will run after intallation anyway.
    if (args.run && args.install) {
        args.install = true;
        args.run = false;
    }

    // Set running as default behavior
    if (!args.run && !args.install && !args.help)
        args.run = true;
}

const rootkit::Args& rootkit::ArgManager::getArgs() const {
    return this->args;
}

void rootkit::ArgManager::help() const {
    std::cout
        << "Help:\n"
        << "--run # Run rootkit\n"
        << "--install # Install rootkit via kernel module (runs from there)\n"
        << "--help # Prints out this help menu\n"
        << "--cwd=<current_working_dir> # Set current working directory\n"
        << "Default behaviour (no arguments) is to run rootkit\n"
        ;
}
