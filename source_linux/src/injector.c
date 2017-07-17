#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
#include <linux/kallsyms.h>
#include <linux/ptrace.h>
#include <linux/random.h>
#include <linux/mm.h>

#include "injector.h"
#include "utils.h"
#include "mem_handling.h"
#include "data.h"
#include "emulator/emulator.h"

#define EMULATOR_STACKSIZE 2048
#define UPPER_BOUND PAGE_ALIGN(0xffff8fff)

#define DO_FORK_ARGS unsigned long clone_flags, unsigned long stack_start, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr, unsigned long tls
#define LATENCY_ENTROPY_ARGS unsigned long clone_flags,unsigned long stack_start,unsigned long stack_size,int __user *child_tidptr,struct pid *pid,int trace,unsigned long tls,int node

__latent_entropy struct task_struct * (* p_copy_process)(LATENCY_ENTROPY_ARGS);
void (*p_wake_up_new_task)(struct task_struct *p);

static struct task_struct *tasks[NMAXTHREADS];
static int no_current_tasks = 0;

struct shrd_region_struct emulator_region_handle[MAXCONCURNPROC] = {{
	.kernel_mem = NULL
}};
static unsigned long bootstrap_addresses[MAXCONCURNPROC], emulator_addresses[MAXCONCURNPROC], stack_addresses[MAXCONCURNPROC], start_ctl_reg, emu_region_size = 0;

static int do_injection(void);
long _do_fork(unsigned long clone_flags, unsigned long stack_start, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr, unsigned long tls);

static int find_processes(char *list[], int listlen, enum SEARCH_MODE mode) {
    struct task_struct *tsk;
    struct vm_area_struct *last_seg = NULL;
    int it = 0, tsk_ok = 0;

    if((list == NULL && listlen != 0) || listlen < 0) {
        printk(KERN_CRIT "Invalid white-/blacklist size!\n");
        return -1;
    }

    emu_region_size = PAGE_ALIGN(bootstraplen + emulatorlen + EMULATOR_STACKSIZE + sizeof(struct runtime_info));

    printk(KERN_INFO "emu: %lu, ctl: %lu\n", emu_region_size, ctl_region_size);

    rcu_read_lock();
    //TODO: Remove the check pid==tid, if "for_each_process" only iterates over the thread group leaders
    for_each_process(tsk) {
        if(tsk->pid == tsk->tgid) {
            // Only take tasks in consideration having PID==TID -> Those are the main threads of a process.
            switch(mode) {
                case WHITELIST:
                    for (it = 0; it < listlen; ++it) {
                        if(!strcmp(list[it], tsk->comm)) {
                            printk("Whitelist process!");
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
                if(tsk->pid < 2500) // Do not inject system processes..
                    continue;

                if(tsk == current) // This process finishes right after LKM init -> Do not use it
                    continue;

                if(!tsk->mm || !tsk->mm->mmap)
                    continue;

                last_seg = tsk->mm->mmap;
                for(; last_seg->vm_next != NULL; last_seg = last_seg->vm_next) ; // Get the last memory segment used by the process

                // TODO: Use last_seg->vm_mm->highest_vm_end to get last address!!

                // Check if there is enough space to inject all neccessary data (ctl_region and emulator + stack)
                if((UPPER_BOUND - last_seg->vm_end) < emu_region_size + ctl_region_size)
                    continue;

                // We can use this process!
                tasks[no_current_tasks] = tsk;

                bootstrap_addresses[no_current_tasks] = UPPER_BOUND - emu_region_size;
                emulator_addresses[no_current_tasks] = bootstrap_addresses[no_current_tasks] + bootstraplen;
                stack_addresses[no_current_tasks] = emulator_addresses[no_current_tasks] + emulatorlen + EMULATOR_STACKSIZE;
                start_ctl_reg = UPPER_BOUND - emu_region_size - ctl_region_size;

                if(++no_current_tasks >= NMAXTHREADS)
                    goto FIN; // Found enough processes!
            }
        }
    }

    FIN:
        rcu_read_unlock();
        return 0;
}

static int do_injection(void) {
    int it = 0, err = 0;
    struct task_struct *tsk;

    // Set the addresses of the shared stack
    for(it = 0; it < NMAXTHREADS; ++it) {
        ctl_region->ctx[it].esp += start_ctl_reg; // main.c -> Contains the offset from the start of the ctl_region
        ctl_region->ctx[it].ebp += start_ctl_reg; // main.c -> Contains the offset from the start of the ctl_region
    }

    //printk(KERN_INFO "Found %d processes!\n", no_current_tasks);
    for(it = 0; it < no_current_tasks; ++it) {
        tsk = tasks[it];

        printk(KERN_INFO "Emulator and Stack: %lu", emu_region_size);

        if(create_shared_mem_region(emu_region_size, emulator_region_handle + it) < 0) {
		    printk(KERN_CRIT "Not able to create the emulator region for process %d!\n", tsk->pid);
		    goto ERR;
	    }

        // Copy the emulator to the new shared memory region
        ((struct runtime_info *)emulator_region_handle[it].kernel_mem)->ctl_reg = (struct ctl_region *)start_ctl_reg;
        ((struct runtime_info *)emulator_region_handle[it].kernel_mem)->dlsym = NULL;
        ((struct runtime_info *)emulator_region_handle[it].kernel_mem)->dlopen = NULL;
        memcpy(emulator_region_handle[it].kernel_mem + sizeof(struct runtime_info), bootstrap, bootstraplen);
        memcpy(emulator_region_handle[it].kernel_mem + sizeof(struct runtime_info) + bootstraplen, emulator, emulatorlen);
    }


    // Do the actual injection!
    for(it = 0; it < no_current_tasks; ++it) {
        tsk = tasks[it];

        printk(KERN_INFO "Injecting into process %d.\n", tsk->pid);

        if((err = share_region(emulator_region_handle + it, tsk, bootstrap_addresses[it]))) {
            printk(KERN_CRIT "Could not inject emulator into process %d", tsk->pid);
            goto ERR;
        }

        if((err = share_region(&ctl_region_handle, tsk, start_ctl_reg))) {
            printk(KERN_CRIT "Could not inject the control region into process %d", tsk->pid);
            goto ERR;
        }

        printk(KERN_CRIT "Injected into process: %d", tsk->pid);
    }

    return 0;

    ERR:
        no_current_tasks = it;
        for(; it < no_current_tasks; ++it) { // Reset everything greater than the current iterator
            tsk = tasks[it];
            if(emulator_region_handle[it].kernel_mem != NULL)
                kfree(emulator_region_handle[it].kernel_mem);
        }
        
        return -1;
}

int inject_processes(char *list[], int listsize, enum SEARCH_MODE mode) {
    int err = 0;

    if((err = find_processes(list, listsize, mode)))
        return err;
    if((err = do_injection()))
        return err;

    return 0;
}

int start_threads(void) {
    int it = 0, *stack_p, stack_it;
    struct task_struct *tsk;
    struct task_struct *(*p_find_task_by_vpid)(pid_t) = NULL;
    long (*p__do_fork)(DO_FORK_ARGS) = NULL;
    struct pt_regs *regs = NULL;

    // TODO: Add nicer method for this job
    p_find_task_by_vpid = (struct task_struct *(*)(pid_t))kallsyms_lookup_name("find_task_by_vpid");
    if(!p_find_task_by_vpid) {
        printk(KERN_CRIT "Not able to locate find_task_by_vpid function!\n");
        goto ERR;
    }

    p__do_fork = (long (*)(DO_FORK_ARGS))kallsyms_lookup_name("_do_fork");
    if(!p__do_fork) {
        printk(KERN_CRIT "Not able to locate _do_fork function!\n");
        goto ERR;
    }

    for(it = 0; it < no_current_tasks; ++it) {
        tsk = tasks[it];
        printk(KERN_INFO "Starting to inject into process %d!\n", tasks[it]->pid);
        //tid = p__do_fork(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND,
        //                    emulator_addresses[it] + EMULATOR_STACKSIZE + emulatorlen,
        //                    EMULATOR_STACKSIZE,
        //                    NULL, NULL, 0);
        //if(tid < 0) {
        //    printk(KERN_CRIT "A thread could not be launched, but we will start the other ones!\n");
        //    ctl_region->pidtab[it] = -1;
        //} else {
        //    ctl_region->pidtab[it] = tid;
        //}

        // The following is really really mangy..., but the kernel does not support cloning with a defined start address..
        send_sig(SIGSTOP, tsk, 1);

        while(tsk->state != TASK_STOPPED) {
            // wait
        }

        rcu_read_lock();

        regs = task_pt_regs(tsk);
        stack_it = 0;
        stack_p = emulator_region_handle[it].kernel_mem + bootstraplen + emulatorlen + sizeof(struct runtime_info) + STACKSIZE - TOP_OF_KERNEL_STACK_PADDING;
        stack_p[stack_it--] = regs->sp;
        stack_p[stack_it--] = regs->bp;
        stack_p[stack_it--] = regs->ax;
        stack_p[stack_it--] = regs->bx;
        stack_p[stack_it--] = regs->cx;
        stack_p[stack_it--] = regs->dx;
        stack_p[stack_it--] = regs->si;
        stack_p[stack_it] = regs->di;

        printk(KERN_INFO "Old ip: 0x%lu\n", regs->ip);

        memcpy(emulator_region_handle[it].kernel_mem + 21 + sizeof(struct runtime_info), &regs->ip, 4);

        //tsk = p_find_task_by_vpid(tid)
        //printk(KERN_INFO "PID of the new thread: %d\n", tid);
        //tsk->state = TASK_STOPPED;
        //tsk->thread.sp0 = tsk->thread.sp = stack_addresses[it];
        regs->ip = bootstrap_addresses[it] + sizeof(struct runtime_info);
        //task_pt_regs(tsk)->bp = stack_addresses[it] - TOP_OF_KERNEL_STACK_PADDING;
        regs->sp = regs->bp = stack_addresses[it] - TOP_OF_KERNEL_STACK_PADDING - 32; // Space for stored register values
        regs->ax = 120;
        regs->bx = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND;
        regs->cx = stack_addresses[it] - TOP_OF_KERNEL_STACK_PADDING;
        regs->dx = regs->di = regs->si = 0;
        //tsk->state = TASK_RUNNING;
        //p_wake_up_new_task(tsk);
        rcu_read_unlock();

        //send_sig(SIGCONT, tsk, 1);
    }

    return 0;

    ERR:
        return -1;
}

long _do_fork(unsigned long clone_flags, unsigned long stack_start, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr, unsigned long tls)
{
	struct task_struct *p;
	int trace = 0;
	long nr;

    // TODO: Add nicer method for this job
    p_copy_process = (__latent_entropy struct task_struct * (*)(LATENCY_ENTROPY_ARGS))kallsyms_lookup_name("copy_process.part.65");
    if(!p_copy_process) {
        printk(KERN_CRIT "Not able to locate copy_process function!\n");
        return -1;
    }

	if (!(clone_flags & CLONE_UNTRACED)) {
		if (clone_flags & CLONE_VFORK)
			trace = PTRACE_EVENT_VFORK;
		else if ((clone_flags & CSIGNAL) != SIGCHLD)
			trace = PTRACE_EVENT_CLONE;
		else
			trace = PTRACE_EVENT_FORK;

		if (likely(!ptrace_event_enabled(current, trace)))
			trace = 0;
	}

	p = p_copy_process(clone_flags, stack_start, stack_size,
			 child_tidptr, NULL, trace, tls, NUMA_NO_NODE);
	add_latent_entropy();
	if (!IS_ERR(p)) {
		struct completion vfork;
		struct pid *pid;

        // TODO: Check if this is necessary
		//trace_sched_process_fork(current, p);

		pid = get_task_pid(p, PIDTYPE_PID);
		nr = pid_vnr(pid);

        // WE DO NOT USE THIS FLAG
		//if (clone_flags & CLONE_PARENT_SETTID)
		//	put_user(nr, parent_tidptr);

		if (clone_flags & CLONE_VFORK) {
			p->vfork_done = &vfork;
			init_completion(&vfork);
			get_task_struct(p);
		}

		//wake_up_new_task(p);

		/* forking complete and child started to run, tell ptracer */
		//if (unlikely(trace))
		//	ptrace_event_pid(trace, pid);

        // WE DO NOT USE THIS FLAG
		//if (clone_flags & CLONE_VFORK) {
		//	if (!wait_for_vfork_done(p, &vfork))
		//		ptrace_event_pid(PTRACE_EVENT_VFORK_DONE, pid);
		//}

		put_pid(pid);
	} else {
		nr = PTR_ERR(p);
	}
	return nr;
}
