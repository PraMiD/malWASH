#ifndef _MEM_HANDLING_H
#define _MEM_HANDLING_H

#include <linux/list.h>
#include <linux/mm.h>
#include <linux/sched.h>

struct task_shrd_region_struct {
    struct vm_area_struct vma;
    struct list_head other_tasks;
    struct task_struct *task;
};

struct shrd_region_struct {
    void *kernel_mem;
    size_t size;
    struct list_head mappings;
};

/**
 *  Create a new shared memory region with the given name.
 *
 *  @param  size        Size of the new memory region.
 *  @param  region      A struct shrd_region_struct* to the newly created memory region. (Valid pointer)
 *  @return             0 on success. < 0 otherwise.
 */
int create_shared_mem_region(ssize_t size, struct shrd_region_struct *region);

/**
 *  Share a given memory region with another process.
 *
 *  @param  region          The region we want to share.
 *  @param  process         The task we want to share the memory with.
 *  @param  start_address   The virtual address the mapping shall start.
 *  @return                 0 on success. < 0 otherwise.
 */
int share_region(struct shrd_region_struct *region, struct task_struct *process, unsigned long start_address);

#endif