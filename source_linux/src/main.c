#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init_task.h>
#include <linux/rculist.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>

#include "utils.h"
#include "data.h"
#include "mem_handling.h"
#include "injector.h"

MODULE_AUTHOR("Marko Dorfhuber");
MODULE_LICENSE("GPL");

#define PROC_NAME "testProc"

struct task_struct *get_my_proc(void);
void print_logo(void);

int create_control_region(void);
int load_segments(void);
int load_modules_tab(void);
int load_function_table(void);
int load_thread_table(void);
int load_init_table(void);
int load_blocks(void);

struct shrd_region_struct ctl_region_handle = {
	.kernel_mem = NULL
};
struct ctl_reg_t *ctl_reg = NULL;
unsigned long ctl_region_size = 0;

void *free_space = NULL; // Pointer to indicate the next free address in the control region
void *segbase[SEGMTABSIZE]; // store segment base addresses

int init_module(void)
{
	struct shrd_region_struct sharing;
	struct task_struct *my_proc = NULL;

	print_logo();

	if(create_control_region()) {
		printk(KERN_CRIT "Not able to create control region!\n");
		goto ERR;
	}

	if(inject_processes(NULL, 0, RANDOM)) {
		printk(KERN_CRIT "Not able to inject the emulator!\n");
		goto ERR;
	}

	if(start_threads()) {
		printk(KERN_CRIT "Unable to start the new emulator threads!\n");
		goto ERR;
	}

	/* if(create_shared_mem_region(PAGE_SIZE, &sharing) < 0) {
		printk(KERN_WARNING "Not able to create a sharing!\\n");
	}
	
	if(!(my_proc = get_my_proc())) {
		printk(KERN_WARNING "Not able to find my process!\\n");
		goto err;
	}

	if(share_region(&sharing, my_proc)) {
		printk(KERN_WARNING "Not able to share the region!\\n");
		goto err;
	}

	printk(KERN_INFO "New sharing created!"); */
	return 0;

	ERR:
		if(sharing.kernel_mem)
			kfree(sharing.kernel_mem);

		// TODO: Add cleanup for emulator regions
		return -EIO;
}

/*
 * Print goodbye message and exit.
 */
void cleanup_module(void)
{
	printk(KERN_INFO "Goodbye!\\n");
}


struct task_struct *get_my_proc(void) {
	struct task_struct *task = &init_task; //Imported from init_task.h -> sched.h
	struct list_head *it = &task->tasks;
	do
	{
		if (strcmp((const char *)task->comm, PROC_NAME) == 0)
			return task;
		it = it->next;
		task = list_entry_rcu(it, struct task_struct, tasks);
	} while(task != &init_task);

	return NULL;
}

void print_logo(void) {
	printk(KERN_INFO "                                                                                       ");
	printk(KERN_INFO "                                                                                  ,--, ");
	printk(KERN_INFO "          ____              ,--,            .---.   ,---,       .--.--.         ,--.'| ");
	printk(KERN_INFO "        ,'  , `.          ,--.'|           /. ./|  '  .' \\     /  /    '.    ,--,  | : ");
	printk(KERN_INFO "     ,-+-,.' _ |          |  | :       .--'.  ' ; /  ;    '.  |  :  /`. / ,---.'|  : ' ");
	printk(KERN_INFO "  ,-+-. ;   , ||          :  : '      /__./ \\ : |:  :       \\ ;  |  |--`  |   | : _' | ");
	printk(KERN_INFO " ,--.'|'   |  || ,--.--.  |  ' |  .--'.  '   \\' .:  |   /\\   \\|  :  ;_    :   : |.'  | ");
	printk(KERN_INFO "|   |  ,', |  |,/       \\ '  | | /___/ \\ |    ' '|  :  ' ;.   :\\  \\    `. |   ' '  ; : ");
	printk(KERN_INFO "|   | /  | |--'.--.  .-. ||  | : ;   \\  \\;      :|  |  ;/  \\   \\`----.   \\'   |  .'. | ");
	printk(KERN_INFO "|   : |  | ,    \\__\\/: . .'  : |__\\   ;  `      |'  :  | \\  \\ ,'__ \\  \\  ||   | :  | ' ");
	printk(KERN_INFO "|   : |  |/     ,' .--.; ||  | '.'|.   \\    .\\  ;|  |  '  '--' /  /`--'  /'   : |  : ; ");
	printk(KERN_INFO "|   | |`-'     /  /  ,.  |;  :    ; \\   \\   ' \\ ||  :  :      '--'.     / |   | '  ,/  ");
	printk(KERN_INFO "|   ;/        ;  :   .'   \\  ,   /   :   '  |--' |  | ,'        `--'---'  ;   : ;--'   ");
	printk(KERN_INFO "'---'         |  ,     .-./---`-'     \\   \\ ;    `--''                    |   ,/       ");
	printk(KERN_INFO "               `--`---'                '---'                              '---'        ");
	printk(KERN_INFO "                                                                                       ");
}

/**
 *	Allocate the control region used by all emulators.
 *	Setup ControlRegion structure and copy all data necessary for execution to the region
 *
 *	@returns	0 on success, <0 if an error occured
 */
int create_control_region(void) {
	int it = 0, err = 0;

	if(create_shared_mem_region(get_size_ctl_region(), &ctl_region_handle) < 0) {
		printk(KERN_WARNING "Not able to create the control region!\n");
		goto ERR;
	}

	ctl_reg = ctl_region_handle.kernel_mem;
	ctl_reg->nblks       = NBLOCKS;                      // set number of blocks
	ctl_reg->nxtblk[0]   = 1;                            // always start with block 1
	ctl_reg->nsegms      = NSEGMS;                       // set number of segments
	ctl_reg->nproc       = NPROC;                        // set number of processses
	ctl_reg->nxtheapaddr = HEAPBASEADDR;                 // that's the base address of shared heap

	for(it = 0; it < NMAXTHREADS; ++it) {
		// We have to place the stack on a defined address
		// => check if this address is available during process selection
		// Maybe we find a better solution for this..
		ctl_reg->ctx[it].esp = STACKBASEADDR + (STACKSIZE + 0x20000)*it + 0x10000;
		ctl_reg->ctx[it].ebp = ctl_reg->ctx[it].esp - 0x80;
		ctl_reg->ctx[it].eax = 0;

		ctl_reg->thrdst[0] = THREAD_UNUSED;
	}

	free_space = ctl_region_handle.kernel_mem + sizeof(struct ctl_reg_t);

	ctl_reg->thrdst[0] = THREAD_RUNNING;


	if((err = load_segments()))
		goto ERR;
	if((err = load_modules_tab()))
		goto ERR;
	if((err = load_function_table()))
		goto ERR;
	if((err = load_thread_table()))
		goto ERR;
	if((err = load_init_table()))
		goto ERR;

	printk(KERN_INFO "Control region setup successful!");

	// TODO: Add command line arguments support here
	// TODO: Allocate shared stack -> Part of the control region!

	printk(KERN_INFO "Starting to inject the emulator...");

	return 0;
ERR:
	if(ctl_region_handle.kernel_mem) {
		kfree(ctl_region_handle.kernel_mem);
		ctl_region_handle.kernel_mem = NULL;
	}

	return err;
}

/**
 *	Load all semgments to the shared memory region.
 *
 *	@returns 	0 on success; <0 otherwise.
 */
int load_segments(void) {
    int it = 0;
	void *p;

	#pragma GCC diagnostic ignored "-Warray-bounds"
    for(p = supsegm[0]; p;  p = supsegm[++it])  // List is NULL terminated
    {
        ctl_reg->segm[it].segmid = it;                         // set index
        ctl_reg->segm[it].startEA = *(void **)p;               // first 4 bytes is start RVA
        ctl_reg->segm[it].endEA = *(void **)(p + 4);           // next  4 bytes is end RVA
		ctl_reg->segm[it].offset = (int)(free_space - (void *)ctl_reg); 
        
        // the name can be random to avoid detection. However we choose such names to make debugging easier.
        snprintf(ctl_reg->segm[it].name, 6, "seg%02d", ctl_reg->segm[it].segmid);
        segbase[it] = free_space;                                  // store base address (we need it for initab relocations)
        memcpy(segbase[it], (void*)(p+8), seglen[it] - 8);            // copy const array to shared region
		free_space += seglen[it] - 8;
	}

	return 0;
}

/**
 *	Copy all modules needed by the program to the shared memory region
 *
 *	@returns	0 on success (Currently the only possible value)
 */
int load_modules_tab(void)
{
    int i, j, k;
    
    for(i = 0, k = 0; i < modtablen; ++i) {					// for each character in modtab (i++ is for skipping newline)       
        i += 2;                                             // first 2 bytes is module id. Skip them

        for(j = 0; modtab[i] != '\n'; ++j)                  // stop copying when you reach a newline
            ctl_reg->modl[k++].name[j] = modtab[i++];          // copy dll name
    
	}
	return 0;
}

/**
 *	Load the function table to the shared memory region.
 *
 *	@returns	0 on success (Currently the only possible value)
 */
int load_function_table(void) {
	memcpy((void *)&ctl_reg->funtab, funtab, funtablen); // Plain array copy
	return 0;
}

/**
 *	Load the function table to the shared memory region.
 *
 *	@returns	0 on success (Currently the only possible value)
 */
int load_thread_table(void) {
	int i = 0, j = 0;
	// slot #0 is reserved for main thread
	for(i = 1, j = 0; i < NMAXTHREADS && thdtab[j]; i++, j += 2) {
        ctl_reg->thrdrtn[i] = thdtab[j];
        ctl_reg->nxtblk[i] = thdtab[j + 1];
    }

	return 0;
}

/**
 *	Do the pointer relocation and "Load the initialized pointer table to the shared memory region."
 *	As there is no value stored to the shared region, we have to check if this function is neccessary...
 *
 *	@returns	0 on success (Currently the only possible value)
 */
int load_init_table(void) {
	int it = 0;
    for(; it < initablen; it += 3 ) {
		// relocate pointer
        // (void *)((int)segbase[initab[3*it]] + initab[3*it+2]) = 
        //(void *)((int)segbase[initab[3*it]] + initab[3*it+2]) - ctl_reg->segm[initab[3*it+1]].startEA +
        //        (SEGMBASEADDR + initab[3*it+1]*SEGMNXTOFF);
	}
	return 0;
}

/**
 *	Load all blocks stored by the IDA plugin to the shared memory region.
 *	For simplicity, we do not create a single shared region for each block.
 *
 *	@returns	0 on success; <0 if an error occured
 */
int load_blocks(void) {
	char blkname[16] = {0};
    void *blkptr;
    int blksize, it = 0;
    

    for(; it < ctl_reg->nblks; ++it) {
        printk(KERN_INFO "[+] Loading block #%d... ", it+1 );
        
        snprintf(blkname, 16, "%d", it+1);

        blksize = blklen[it];
        blkptr = free_space;
		free_space += blksize;

        memcpy(blkptr, supblk[it], blksize);

        if( *(unsigned short*)(blkptr + 4) < MAXNBLKS ) { // overflow?
			ctl_reg->blk[*(unsigned short *)(blkptr + 4)].offset = (int)(free_space - (void *)ctl_reg);
            strncpy(ctl_reg->blk[*(unsigned short *)(blkptr + 4)].name, blkname, 8);
		}
        else {
			printk(KERN_ALERT "Overflow detected in block #%d. Try to increase MAXNBLKS!", it);
			return -1;
		}
    }

	return 0;
}