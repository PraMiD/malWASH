#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>

#include "mem_handling.h"

static void mem_open(struct vm_area_struct *);
static void mem_close(struct vm_area_struct *);

static int find_vma_links(struct mm_struct *, unsigned long,
		unsigned long, struct vm_area_struct **,
		struct rb_node ***, struct rb_node **);

static struct vm_operations_struct vm_ops = {
    .open =  mem_open,
    .close = mem_close,
};


/*
 * Create a new shared memory region.
 */
int create_shared_mem_region(ssize_t size, struct shrd_region_struct *region)
{
    if(!region || size == 0)
        goto err;
	
    if(!(region->kernel_mem = kmalloc(size, GFP_KERNEL))) {
		goto err;
	}

	region->size = size;
    INIT_LIST_HEAD(&region->mappings);
    return 0;

    err:
        if(region && region->kernel_mem)
            kfree(region->kernel_mem);
        return -1;
}

int share_region(struct shrd_region_struct *region, struct task_struct *process, unsigned long start_address) {
	struct vm_area_struct *last_seg, *new_seg, *prev = NULL;
	struct rb_node **rb_link = NULL, *rb_parent = NULL;
    struct task_shrd_region_struct *sharing = NULL;

    static void (*p_vma_set_page_prot)(struct vm_area_struct *) = NULL;
    static void (*p_vm_stat_account)(struct mm_struct *, vm_flags_t, long) = NULL;
    static void (*p___vma_link_rb)(struct mm_struct *, struct vm_area_struct *, struct rb_node **, struct rb_node *) = NULL;

    // TODO: Add nicer method to do these jobs!
	p_vma_set_page_prot = (void (*)(struct vm_area_struct *))kallsyms_lookup_name("vma_set_page_prot");
	p_vm_stat_account = (void (*)(struct mm_struct *, vm_flags_t, long))kallsyms_lookup_name("vm_stat_account");
	p___vma_link_rb = (void (*)(struct mm_struct *, struct vm_area_struct *, struct rb_node **, struct rb_node *))kallsyms_lookup_name("__vma_link_rb");

    if(!p_vma_set_page_prot || !p_vm_stat_account || !p___vma_link_rb) {
        goto err;
	}

	if(!region || !process) {
		goto err;
	}

    if(!(sharing = kmalloc(sizeof(struct task_shrd_region_struct), GFP_KERNEL))) {
        goto err;
	}
	
	sharing->task = process;
    new_seg = &(sharing->vma);

	// TODO: Check if we can omit this part. All values should be filled out by ourself.
    last_seg = process->mm->mmap;
	if(!last_seg) 
        goto err;
	for(; last_seg->vm_next != NULL; last_seg = last_seg->vm_next) ; // Get the last stored memory segment


	down_write(&process->mm->mmap_sem);
	memcpy(new_seg, last_seg, sizeof(struct vm_area_struct)); // Copy the values of the last region as a "starting point"

	new_seg->vm_mm = process->mm;
	new_seg->vm_start = start_address; // Append directly to the last region
	new_seg->vm_end = new_seg->vm_start + region->size;
	new_seg->vm_flags |= VM_LOCKED | VM_DONTEXPAND | VM_DONTDUMP;
	new_seg->vm_page_prot = vm_get_page_prot(new_seg->vm_flags);
	new_seg->vm_pgoff = 0;
	new_seg->vm_ops = &vm_ops;

	INIT_LIST_HEAD(&new_seg->anon_vma_chain);
	find_vma_links(new_seg->vm_mm, new_seg->vm_start, new_seg->vm_end, &prev, &rb_link, &rb_parent);
	new_seg->vm_next = prev->vm_next; // We searched the last element => next == NULL
	new_seg->vm_prev = last_seg;
	last_seg->vm_next = new_seg;
	p___vma_link_rb(new_seg->vm_mm, new_seg, rb_link, rb_parent);

	p_vm_stat_account(process->mm, new_seg->vm_flags, (new_seg->vm_end - new_seg->vm_start) >> PAGE_SHIFT);
	new_seg->vm_flags |= VM_SOFTDIRTY;
	p_vma_set_page_prot(new_seg);

	up_write(&process->mm->mmap_sem);

	printk(KERN_INFO "Mapping virtual memory from 0x%lx to 0x%lx", new_seg->vm_start, new_seg->vm_end);


  	if (remap_pfn_range(new_seg, new_seg->vm_start,
                     virt_to_phys((void*)((unsigned long)region->kernel_mem)) >> PAGE_SHIFT,
                     region->size,
                     PAGE_SHARED))
	{
    	printk("remap page range failed\n");
     	goto err;
	}

	up_write(&process->mm->mmap_sem);

    list_add_tail(&sharing->other_tasks, &region->mappings);

	printk(KERN_INFO "Your start address: 0x%lx\n", new_seg->vm_start);
	return 0;

    err:
        if(sharing)
            kfree(sharing);
        return -1;
}

static void mem_open(struct vm_area_struct *vma)
{
    printk(KERN_INFO "The shared memory was opened. Do we know this process? Use this for protection mechanisms.");
}

static void mem_close(struct vm_area_struct *vma)
{
    printk(KERN_INFO "One process where we injected the emulator was closed => use the LKM to inject another process.\n");
}

static int find_vma_links(struct mm_struct *mm, unsigned long addr,
		unsigned long end, struct vm_area_struct **pprev,
		struct rb_node ***rb_link, struct rb_node **rb_parent)
{
	struct rb_node **__rb_link, *__rb_parent, *rb_prev;

	__rb_link = &mm->mm_rb.rb_node;
	rb_prev = __rb_parent = NULL;

	while (*__rb_link) {
		struct vm_area_struct *vma_tmp;

		__rb_parent = *__rb_link;
		vma_tmp = rb_entry(__rb_parent, struct vm_area_struct, vm_rb);

		if (vma_tmp->vm_end > addr) {
			/* Fail if an existing vma overlaps the area */
			if (vma_tmp->vm_start < end)
				return -ENOMEM;
			__rb_link = &__rb_parent->rb_left;
		} else {
			rb_prev = __rb_parent;
			__rb_link = &__rb_parent->rb_right;
		}
	}

	*pprev = NULL;
	if (rb_prev)
		*pprev = rb_entry(rb_prev, struct vm_area_struct, vm_rb);
	*rb_link = __rb_link;
	*rb_parent = __rb_parent;
	return 0;
}