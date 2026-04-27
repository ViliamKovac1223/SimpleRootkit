#ifndef ROOTKIT_COMMON_H
#define ROOTKIT_COMMON_H

#include <asm-generic/int-ll64.h>

#define PROG_01 1
#define PROG_02 2

#define MAX_FILENAME_LEN 32

struct event {
    unsigned long long inode;
    char filename[MAX_FILENAME_LEN];
};

struct conn_info {
    int id;
    __u32 daddr;
    __u16 dport;
};

#define IOC_MAGIC 't'
#define IOCTL_SEND_DATA _IOW(IOC_MAGIC, 1, struct conn_info)
#define DEV_NAME "conn_dev"

#endif
