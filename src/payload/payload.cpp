#include <csignal>
#include <iostream>
#include <atomic>
#include <unistd.h>
#include <chrono>
#include <thread>

std::atomic<bool> should_exit(false);

void payload_function();
void signal_handler(int signum);

int main(int argc, char ** argv) {
    std::cout << "Hello from payload. PID: " << getpid() << std::endl;

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    // Wait till signal to stop working
    while (!should_exit) {
        payload_function();
    }

    return 0;
}

void payload_function(){
    std::cout << "payload is runnig" << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(1));
}

void signal_handler(int signum) {
    std::cout << "Payload received signal " << signum << ". Exiting gracefully." << std::endl;
    should_exit = true;
}
