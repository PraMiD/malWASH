#ifndef _DATA_COPY_H
#define _DATA_COPY_H

#include "utils.h"

/**
 *  Load all segments to shared memory
 */
void loadsegms(void);

/**
 *  Load the module table to shared memory
 */
void loadmodtab(void);

/**
 *  Load function table to shared memory
 */
void loadfuntab(void);

/**
 *  Load thread table to shared memory
 */
void loadthdtab(void);

/**
 *  Load table of initialized pointers to shared memory
 */
void loadinitab(void);

/**
 *  Load basic blocks to shared memory
 */
void loadblks(void);     

#endif