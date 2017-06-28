#ifndef _EMULATOR_H
#define _EMULATOR_H

#include "../ctl_region.h"

struct runtime_info {
    struct ctl_region *ctl_region;
    // Virtual address of the mapping of libdl-xx.
    // We assume that this part of the mapped library contains the ELF header.
    void *libdl_start;
    void *dlopen, *dlsym; // Those will be set by the emulator
};

#endif