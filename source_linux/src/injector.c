#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
#include <linux/kallsyms.h>

#include "injector.h"
#include "utils.h"
#include "mem_handling.h"
#include "data.h"

#define EMULATOR_STACKSIZE 2048

#define DO_FORK_ARGS unsigned long clone_flags, unsigned long stack_start, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr, unsigned long tls

static struct task_struct *tasks[NMAXTHREADS];
static int no_current_tasks = 0;

struct shrd_region_struct emulator_region_handle[MAXCONCURNPROC] = {{
	.kernel_mem = NULL
}};
static unsigned long emulator_addresses[MAXCONCURNPROC], stack_addresses[MAXCONCURNPROC], start_ctl_reg;

static int do_injection(void);

static int find_processes(char *list[], int listlen, enum SEARCH_MODE mode) {
    struct task_struct *tsk;
    struct vm_area_struct *last_seg = NULL;
    int it = 0, tsk_ok = 0;

    rcu_read_lock();
    //TODO: Remove the check pid==tid, if "for_each_process" only iterates over the thread group leaders
    for_each_process(tsk) {
        if(tsk->pid == tsk->tgid) {
            // Only take tasks in consideration having PID==TID -> Those are the main threads of a process.
            switch(mode) {
                case WHITELIST:
                    for (it = 0; it < listlen; ++it) {
                        if(strcmp(list[it], tsk->comm)) {
                            tsk_ok = 1;
                            break;
                        }
                    }
                    break;
                case BLACKLIST:
                    tsk_ok = 1;
                    for (it = 0; it < listlen; ++it) {
                        if(strcmp(list[it], tsk->comm)) {
                            tsk_ok = 0;
                            break;
                        }
                    }
                    break;
                default: // Also include RANDOM
                    tsk_ok = 1;
                    break;
            }

            if(tsk_ok) {
                // Check if there is enough space to inject all neccessary data (ctl_region and emulator + stack)
                last_seg = tsk->mm->mmap;
                if(!last_seg)
                    continue;
                for(; last_seg->vm_next != NULL; last_seg = last_seg->vm_next) ; // Get the last memory segment used by the process
                
                if((last_seg->vm_mm->highest_vm_end - last_seg->vm_end) < (get_size_ctl_region() + emulatorlen + EMULATOR_STACKSIZE))
                    continue;
                
                // We can use this process!
                tasks[no_current_tasks] = tsk;

                // Pray that the size of all VM mappings is the same..
                start_ctl_reg = last_seg->vm_mm->highest_vm_end - get_size_ctl_region();
                stack_addresses[no_current_tasks] = last_seg->vm_mm->highest_vm_end;
                emulator_addresses[no_current_tasks++] = last_seg->vm_mm->highest_vm_end - (get_size_ctl_region() + emulatorlen + EMULATOR_STACKSIZE);
            }
        }
    }
    rcu_read_unlock();
}

static int do_injection(void) {
    int it = 0, err = 0;
    struct task_struct *tsk;

    for(it = 0; it < no_current_tasks; ++it) {
        tsk = tasks[it];

        if(create_shared_mem_region(emulatorlen + STACKSIZE, emulator_region_handle + it) < 0) {
		    printk(KERN_CRIT "Not able to create the emulator region for process %d!\n", tsk->pid);
		    goto ERR;
	    }
    }

    // Copy the emulator to the new shared memory region
    memcpy(emulator_region_handle[it].kernel_mem, emulator, emulatorlen);


    // Do the actual injection!
    for(it = 0; it < no_current_tasks; ++it) {
        tsk = tasks[it];

        if((err = share_region(emulator_region_handle + it, tsk, emulator_addresses[it]))) {
            printk(KERN_CRIT "Could not inject emulator into process %d", tsk->pid);
            goto ERR;
        }
        if((err = share_region(&ctl_region_handle, tsk, start_ctl_reg))) {
            printk(KERN_CRIT "Could not inject the control region into process %d", tsk->pid);
            goto ERR;
        }
    }

    return 0;

    ERR:
        for(it = 0; it < no_current_tasks; ++it) {
            tsk = tasks[it];
            if(emulator_region_handle[it].kernel_mem != NULL)
                kfree(emulator_region_handle[it].kernel_mem);
        }
        
        no_current_tasks = it;
        return -1;
}

int start_threads(void) {
    int it = 0, tid = 0;
    long (*p__do_fork)(DO_FORK_ARGS) = NULL;
    struct task_struct *tsk;

    // TODO: Add nicer method for this job
    p__do_fork = (long (*)(DO_FORK_ARGS))kallsyms_lookup_name("_do_fork");
    if(!p__do_fork) {
        printk(KERN_CRIT "Not able to locate _do_fork function!\n");
        goto ERR;
    }

    for(it = 0; it < no_current_tasks; ++it) {
        printk(KERN_INFO "Starting to inject into process %d!\n", tasks[it]->pid);
        tid = p__do_fork(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND,
                            emulator_addresses[it] + EMULATOR_STACKSIZE + emulatorlen,
                            EMULATOR_STACKSIZE,
                            NULL, NULL, 0);
        if(tid < 0) {
            printk(KERN_CRIT "A thread could not be launched, but we will start the other ones!\n");
            ctl_reg->pidtab[it] = -1;
        } else {
            ctl_reg->pidtab[it] = tid;
        }

        tsk->state = TASK_STOPPED;
        rcu_read_lock();
        // The following is really really mangy..., but the kernel does not support cloning with a defined start address..
        tsk = find_task_by_vpid(tid);
        tsk->thread.sp0 = tsk->thread.sp = stack_addresses[it];
        task_pt_regs(tsk)->ip = emulator_addresses[it];
        task_pt_regs(tsk)->bp = stack_addresses[it] - TOP_OF_KERNEL_STACK_PADDING;
        task_pt_regs(tsk)->sp = stack_addresses[it] - TOP_OF_KERNEL_STACK_PADDING;
        rcu_read_unlock();
        tsk->state = TASK_RUNNING;
    }

    ERR:
        return -1;
}