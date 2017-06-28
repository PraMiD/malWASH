#ifndef _UTILS_H
#define _UTILS_H
/**
 *  This module provides helper methods for all parts of the kernel module.
 *  In addition, we store publicly available data here, eg the shared regions.
 */

 #include "ctl_region.h"

/*  DATA    */
extern struct shrd_region_struct ctl_region_handle;
extern struct ctl_region *ctl_region;
extern unsigned long ctl_region_size;


/*  FUNCTIONS   */
void reasm(void);

/**
 *	Calculate the control region's size to caontain all necessary data.
 *
 *	@returns 	The size of the control region.
 */
unsigned long get_size_ctl_region(void);
#endif