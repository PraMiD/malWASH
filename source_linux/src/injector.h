#ifndef _INJECTOR_H
#define _INJECTOR_H

#include <linux/types.h>

/**
 *  This module contains methods to inject the emulator in different processes.
 *  Whitelisting and blacklisting is currently supported.
 *
 *  The major porblem is to find processes suitable for injection as the data section
 *  (= control region) must be at the same virtual address in every address space.
 *  The reason for this is, that we share the registers over multiple address spaces and the
 *  registers can point to the data region.
 *
 *  However the LKM-based approach has the advantage, that we have the possibility to seach
 *  for suitable processes by checking if the chosen memory region is used by the process itself.
 *  Therefore, the LKM-based approach is more robust than the remote injection-based used in the
 *  Windows implementation.
 */

 enum SEARCH_MODE {
     WHITELIST,
     BLACKLIST,
     RANDOM
 };

/**
 *  Inject the emulator in up to n processes.
 */
int inject_processes(char *[], enum SEARCH_MODE);

#endif