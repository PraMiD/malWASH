#include <linux/types.h>
#include <linux/slab.h>
#include <linux/mm.h>

#include "utils.h"
#include "data.h"

unsigned long get_size_ctl_region(void) {
	int it = 0;

	if(!ctl_region_size) {
		ctl_region_size = sizeof(struct ctl_region);

		for(it = 0; it < NBLOCKS; ++it)
			ctl_region_size += blklen[it];
		for(it = 0; it < NSEGMS; ++it)
			ctl_region_size += seglen[it];
	}
	ctl_region_size = PAGE_ALIGN(ctl_region_size);
	return ctl_region_size;
}