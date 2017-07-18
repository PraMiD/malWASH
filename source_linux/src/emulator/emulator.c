// Compile with gcc emulator.c -O0 -nostdlib -fPIC -o emulator
#include <elf.h>

#include "../ctl_region.h"
#include "emulator.h"

#define BOOTSTRAP_SIZE 28

#define LIBDL_NAME "libdl.so.2"
#define DL_OPEN_NAME "dlopen"
#define DL_SYM_NAME "dlsym"
#define DYNSTR_NAME ".dynstr"
#define EXEC_REGION_SIZE 1000

#define DLOPEN_OFFSET 0xc60
#define DLSYM_OFFSET 0xd70

#define NULL 0

#define NOP asm volatile ( "nop" ::: "memory");
#define NOP2 NOP  NOP
#define NOP4 NOP2  NOP2
#define NOP8 NOP4  NOP4
#define NOP16 NOP8  NOP8
#define NOP32 NOP16  NOP16
#define NOP64 NOP32  NOP32
#define NOP128 NOP64  NOP64
#define NOP256 NOP128  NOP128
#define NOP512 NOP256  NOP256
#define NOP1024 NOP512  NOP512


int lock(int, struct runtime_info *);
int execute(int, struct runtime_info *);
int get_libdl_functions(struct runtime_info *);
int strncmp(char *, char *, int);
char *find_str(int, char *, unsigned);
void my_memcpy(void *src, void *dst, unsigned len);
void push_emulated(unsigned int, int, struct runtime_info *);
unsigned int pop_emulated(int, struct runtime_info *);

/*#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <assert.h>
#include <dlfcn.h>

#define FILEPATH "/home/marko/libdl.so.2"
#define NUMINTS  (1000)
#define FILESIZE (NUMINTS * sizeof(int))

unsigned getFilesize(const char* filename) {
    struct stat st;
    stat(filename, &st);
    return st.st_size;
}

int main(int argc, char** argv) {
    int i;
    unsigned filesize = getFilesize(FILEPATH);
    //Open file
    int fd = open(FILEPATH, O_RDONLY, 0);
    assert(fd != -1);
    //Execute mmap
    void* mmappedData = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd, 0);
    assert(mmappedData != MAP_FAILED);
    
    struct runtime_info rt_info;
    rt_info.libdl_start = mmappedData;
    get_libdl_functions(&rt_info);

    printf("dlopen from so parsing: %p\n", rt_info.dlopen);
    printf("dlopen after relocation: %p\n", dlopen);

    scanf("%d", &i);

    return 0;
}*/

int _start()
{
    void *_start_addr;
    struct runtime_info *rt_info;

    asm volatile (  ".intel_syntax noprefix;"
                    "call get_ip;"
                    "get_ip:;"
                    "pop %0;"
                    "sub %0, 0x15;" // _start_addr now contains the address of _start in memory
                    ".att_syntax;"
        : "=r" (_start_addr)
        :: "memory" );

    rt_info = _start_addr - BOOTSTRAP_SIZE - sizeof(struct runtime_info);
    
    while(1) 
    {
        if(lock(0, rt_info))
        {
            execute(0, rt_info);
        }
    }
}

/**
 *  Try to gain the mutex of the thread with the given number.
 *
 *  @param thrd_no  Number of the thread we want to execute a block from.
 *  @param ctl_region  Address of our control region.
 *
 *  @return 1 if we are allowed to execute, 0 if not!
 */
int lock(int thrd_no, struct runtime_info *rt_info)
{
    int res = 0;
    int *lock_addr = rt_info->ctl_reg->mutex + thrd_no;
    asm volatile (  ".intel_syntax noprefix;"
                    "bts %1, 0;"
                    "jnc short already_locked;"
                    "mov %0, 1;"
                    "already_locked:;"
                    ".att_syntax;"
    : "=r" (res)
    : "r" (lock_addr)
    : "memory");

    return res;
}

int execute(int thrd_no, struct runtime_info *rt_info)
{
    struct ctl_region *ctl_reg = rt_info->ctl_reg;
    char *it_addr; // We use char * here for easier searching -> ++ increments exactly one byte
    void **block_start, **segm_table, **reloc_addr; // Just some address..
    unsigned it, segm_id;
    void *emulator_esp;

    // Load the next block of the given thread
    // Find BBLK and skip the mark and the block size
    // 0x4b4c4242 == BBLK in big endian
    block_start = (void **)find_str(0x4b4c4242, ((char *)ctl_reg) + ctl_reg->blk[ctl_reg->nxtblk[thrd_no] - 1].offset, sizeof "BBLK" - 1);
    block_start = (void **)(((unsigned int) block_start) + 6);
    // TODO: We know the block length -> Find out if the length includes the length field and calculate the segment start from these values
    // 0x4d474553 == SEGM in big endian
    segm_table = (void **)find_str(0x4d474553, (char *)block_start, sizeof "SEGM" - 1);
    my_memcpy(block_start, &&block_execute_region, *((short *)(((char *)block_start) - 2)));

    for(it_addr = (char *)segm_table + 4; *(void **)it_addr != (void *)0x434E5546; it_addr += 8) {
        segm_id = *(unsigned *)(it_addr + 4);
        reloc_addr = (void **)it_addr; // POINTER to the address we have to relocate

        // Do the section relocation
        // Address = offset_in_segment + new_segment_start
        // offset_in_segment = old_address - old_segment_start
        *reloc_addr = *reloc_addr - ctl_reg->segm[segm_id].startEA + (((void **)ctl_reg) + ctl_reg->segm[segm_id].offset);
    }

    // TODO: Relocation of imported functions: exec.cpp.843
    // TODO: Duplicate handles and sockets
    // TODO: Handle heap minipulation

    // We know that we hold the semaphore for the given thread -> Simply start execution
    // Save emulator context and load process context

    for(it_addr = &&after_block_exec; *(void **)it_addr != (void *)0x01020304; it_addr++) ; // Find the address where we restore the right esp

    //exec_region[EXEC_REGION_SIZE- 5] = 0xFF;
    //((void **)exec_region)[EXEC_REGION_SIZE - 4] = &&after_exec;
    asm volatile (  ".intel_syntax noprefix;"
                    "push eax;"
                    "push ebx;"
                    "push ecx;"
                    "push edx;"
                    "push esi;"
                    "push edi;"
                    "pushfd;"
                    "push ebp;"

                    "mov [%0], esp;"
                    ".att_syntax;"
    :: "r" (it_addr)
    : "memory");

    //*(void **)it_addr = emulator_esp; // Insert the address of out esp

    // Prepare emulated program's stack
    push_emulated(ctl_reg->ctx[thrd_no].eax, thrd_no, rt_info);
    push_emulated(ctl_reg->ctx[thrd_no].ebx, thrd_no, rt_info);
    push_emulated(ctl_reg->ctx[thrd_no].ecx, thrd_no, rt_info);
    push_emulated(ctl_reg->ctx[thrd_no].edx, thrd_no, rt_info);
    push_emulated(ctl_reg->ctx[thrd_no].esi, thrd_no, rt_info);
    push_emulated(ctl_reg->ctx[thrd_no].edi, thrd_no, rt_info);
    push_emulated(ctl_reg->ctx[thrd_no].eflags, thrd_no, rt_info);
    push_emulated(ctl_reg->ctx[thrd_no].ebp, thrd_no, rt_info);


    asm volatile (  ".intel_syntax noprefix;"
                    "mov esp, %0;"
                    "pop ebp;"
                    "popfd;"
                    "pop edi;"
                    "pop esi;"
                    "pop edx;"
                    "pop ecx;"
                    "pop ebx;"
                    "pop eax;"
                    ".att_syntax;"
    :: "r" (ctl_reg->ctx[thrd_no].esp)
    : "memory");

    block_execute_region:
    NOP1024

    after_block_exec:
    asm volatile (  ".intel_syntax noprefix;"
                    "push eax;"
                    "push ebx;"
                    "push ecx;"
                    "push edx;"
                    "push esi;"
                    "push edi;"
                    "pushfd;"
                    "push ebp;"

                    "mov eax, esp;" // store current esp in eax -> possible to resore esp and ebp of the
                                    // emulator and to access local variables directly
                    "mov esp, 0x01020304;" // Restore esp; Address replaced before execution
                    "pop ebp;" // Restore ebp
                    ".att_syntax;"
    ::: "memory");
    asm volatile (  ".intel_syntax noprefix;"
                    "mov [%1], ebx;" // ebp and esp are restored -> We can store esp_mem and nxt_blk
                    "mov [%0], eax;"
                    "popfd;"
                    "pop edi;"
                    "pop esi;"
                    "pop edx;"
                    "pop ecx;"
                    "pop ebx;"
                    "pop eax;"
                    ".att_syntax;"
    :: "r" (&ctl_reg->ctx[thrd_no].esp), "r" (&ctl_reg->nxtblk[thrd_no])
    : "memory", "eax", "ebx");

    // Store emulated program's register values in global region
    ctl_reg->ctx[thrd_no].ebp = pop_emulated(thrd_no, rt_info);
    ctl_reg->ctx[thrd_no].eflags = pop_emulated(thrd_no, rt_info);
    ctl_reg->ctx[thrd_no].edi = pop_emulated(thrd_no, rt_info);
    ctl_reg->ctx[thrd_no].esi = pop_emulated(thrd_no, rt_info);
    ctl_reg->ctx[thrd_no].edx = pop_emulated(thrd_no, rt_info);
    ctl_reg->ctx[thrd_no].ecx = pop_emulated(thrd_no, rt_info);
    ctl_reg->ctx[thrd_no].ebx = pop_emulated(thrd_no, rt_info);
    ctl_reg->ctx[thrd_no].eax = pop_emulated(thrd_no, rt_info);
}

void push_emulated(unsigned int value, int thrd_no, struct runtime_info *rt_info)
{
    struct ctl_region *ctl_reg = rt_info->ctl_reg;

    ctl_reg->ctx[thrd_no].esp = ctl_reg->ctx[thrd_no].esp - 4;
    *(unsigned int *)(ctl_reg->ctx[thrd_no].esp) = value;
}

unsigned int pop_emulated(int thrd_no, struct runtime_info *rt_info)
{
    struct ctl_region *ctl_reg = rt_info->ctl_reg;

    ctl_reg->ctx[thrd_no].esp = ctl_reg->ctx[thrd_no].esp + 4;
    return *(unsigned int *)(ctl_reg->ctx[thrd_no].esp - 4);
}

// Use an integer as mark here -> No data section is injected...
char *find_str(int mark, char *start, unsigned len)
{
    int it = 0;
    if(mark == NULL || start == NULL)
        return NULL;
    
    while(1) { // Pray that we find the string...
        while(*start != *(char *)&mark)
            start++;

        if(strncmp((char *)&mark, start, len))
            return start;
        start++;
    }

    return NULL; // Dead, but the compiler does not know it ;)
}

void my_memcpy(void *src, void *dst, unsigned len)
{
    unsigned it = 0;
    while(it < len) {
        ((char *)dst)[it] = ((char *)src)[it];
        it++;
    }
}

/**
 *  Compare two strings for equality.
 *
 *  @param      s1  First string.
 *  @param      s2  Second string.
 *  @return         0 if the strings are unequal, 1 otherwise.
 */
int strncmp(char *s1, char *s2, int n)
{
    int it = 0;

    if(s1 == '\0' || s2 == '\0')
        return 0;
    
    // < n as we compare strings that are not NULL terminated
    for(it = 0; it < n && s1[it] != '\0' && s2[it] != '\0'; it++) {
        if (s1[it] != s2[it])
            return 0;
    }

    if(it == n)
        return 1;
    return 0;
}