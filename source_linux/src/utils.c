#include <linux/types.h>

#include "utils.h"
#include "data.h"

size_t get_size_ctl_region(void) {
	int it = 0;

	if(!ctl_region_size) {
		ctl_region_size = sizeof(struct ctl_reg_t);

		for(it = 0; it < ctl_reg->nblks; ++it)
			ctl_region_size += blklen[it];
	}
	return ctl_region_size;
}