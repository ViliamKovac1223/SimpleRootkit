#ifndef BPF_COMMON_H
#define BPF_COMMON_H

#define PROG_01 1
#define PROG_02 2

#define MAX_FILENAME_LEN 32

struct event {
    unsigned long long inode;
    char filename[MAX_FILENAME_LEN];
};

#endif
