// Compile with gcc emulator.c -O0 -nostdlib -fPIC -o emulator
#include <elf.h>

#include "../ctl_region.h"
#include "emulator.h"

#define LIBDL_NAME "libdl.so.2"
#define DL_OPEN_NAME "dlopen@@GLIBC_2.1"
#define DL_SYM_NAME "dlsym@@GLIBC_2.0"

int lock(int, struct runtime_info *);
int get_libdl_functions(struct runtime_info *);
int strncmp(char *, char *, int);


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

    rt_info = _start_addr - sizeof(struct runtime_info);
    rt_info->dlopen = 0;
    rt_info->dlsym = 0;
    get_libdl_functions(rt_info);
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
    int *lock_addr = rt_info->ctl_region->mutex + thrd_no;
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


int get_libdl_functions(struct runtime_info *rt_info)
{
    Elf32_Ehdr *ehdr = rt_info->libdl_start;
    Elf32_Shdr *shdr, *shdrs_start = (Elf32_Shdr *)(((char *)ehdr) + ehdr->e_shoff);
    Elf32_Sym *symbol;
    char *strtab = ((char *)ehdr) + ((shdrs_start + ehdr->e_shstrndx))->sh_offset;
    int sec_it = 0, sym_it = 0;

    for(sec_it = 0; sec_it < ehdr->e_shnum; ++sec_it) {
        // Iterate over all sections to find .dynsym
        shdr = shdrs_start + sec_it;
        if(shdr->sh_type == SHT_SYMTAB)
        {
            // Ok we found the right section

            for(sym_it = 0; sym_it < shdr->sh_size / sizeof(Elf32_Sym); ++sym_it) {
                symbol = (Elf32_Sym *)((char *)ehdr) + shdr->sh_offset;

                if(strncmp(strtab + symbol->st_name, DL_OPEN_NAME, sizeof DL_OPEN_NAME))
                {
                    rt_info->dlopen = ((char *)shdr) + (symbol->st_value - shdr->sh_addr);
                } else if(strncmp(strtab + symbol->st_name, DL_SYM_NAME, sizeof DL_SYM_NAME))
                {
                    rt_info->dlsym = ((char *)shdr) + (symbol->st_value - shdr->sh_addr);
                }

                if(rt_info->dlopen != 0 && rt_info->dlsym != 0)
                    return 0;
            }

            break; // Do not have to do further search
        }
    }

    return -1;
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
    
    for(it = 0; it <= 0 && s1[it] != '\0' && s2[it] != '\0'; it++) {
        if (s1[it] != s2[it])
            return 0;
    }

    return 1;
}