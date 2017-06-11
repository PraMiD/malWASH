#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/kallsyms.h>

#include "injector.h"
#include "utils.h"
#include "mem_handling.h"
#include "data.h"

#define EMULATOR_STACKSIZE 2048

#define DO_FORK_ARGS unsigned long clone_flags, unsigned long stack_start, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr, unsigned long tls

static struct task_struct *tasks[NMAXTHREADS];
static int no_current_tasks;

struct shrd_region_struct emulator_region_handle[MAXCONCURNPROC] = {{
	.kernel_mem = NULL
}};
static unsigned long emulator_addresses[MAXCONCURNPROC], start_ctl_reg;

static int do_injection(void);


static int find_processes(char *list[], enum SEARCH_MODE mode) {
    struct task_struct *tsk;

    rcu_read_lock();
    //TODO: Remove the check pid==tid, if "for_each_process" only iterates over the thread group leaders
    for_each_process(tsk) {
        if(tsk->pid == tsk->tgid) {
            // Only take tasks in consideration having PID==TID -> Those are the main threads of a process.
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

    // TODO: Add nicer method for this job
    p__do_fork = (long (*)(DO_FORK_ARGS))kallsyms_lookup_name("_do_fork");
    if(!p__do_fork) {
        printk(KERN_CRIT "Not able to locate _do_fork function!\n");
        goto ERR;
    }

    for(it = 0; it < no_current_tasks; ++it) {
        tid = p__do_fork(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND,
                            emulator_addresses[it] + EMULATOR_STACKSIZE + emulatorlen,
                            EMULATOR_STACKSIZE,
                            NULL, NULL, 0);
        printk(KERN_INFO "Starting to inject into process %d!\n", tasks[it]->pid);
        if(tid < 0) {
            printk(KERN_CRIT "A thread could not be launched, but we will start the other ones!\n");
            ctl_reg->pidtab[it] = -1;
        }
        else {
            ctl_reg->pidtab[it] = tid;
        }
    }

    ERR:
        return -1;
}