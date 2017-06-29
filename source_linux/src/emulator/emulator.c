// Compile with gcc emulator.c -O0 -nostdlib -fPIC -o emulator
#include <elf.h>

#include "../ctl_region.h"
#include "emulator.h"

#define LIBDL_NAME "libdl.so.2"
#define DL_OPEN_NAME "dlopen"
#define DL_SYM_NAME "dlsym"
#define DYNSTR_NAME ".dynstr"

int lock(int, struct runtime_info *);
int get_libdl_functions(struct runtime_info *);
int strncmp(char *, char *, int);


#include <stdio.h>
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

size_t getFilesize(const char* filename) {
    struct stat st;
    stat(filename, &st);
    return st.st_size;
}

int main(int argc, char** argv) {
    int i;
    size_t filesize = getFilesize(FILEPATH);
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
}

/*int _start()
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
}*/

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

void *get_dynstr_section(struct runtime_info *rt_info)
{
    Elf32_Ehdr *ehdr = rt_info->libdl_start;
    Elf32_Shdr *shdr, *shdrs_start = (Elf32_Shdr *)(((char *)ehdr) + ehdr->e_shoff);
    char *strtab = ((char *)ehdr) + ((shdrs_start + ehdr->e_shstrndx))->sh_offset;
    int sec_it = 0;

    for(sec_it = 0; sec_it < ehdr->e_shnum; ++sec_it) {
        // Iterate over all sections to find .dynstr section
        shdr = shdrs_start + sec_it;
        if(shdr->sh_type == SHT_STRTAB && strncmp(strtab + shdr->sh_name, DYNSTR_NAME, sizeof DYNSTR_NAME))
            return ((char *)ehdr) + shdr->sh_offset;
    }

    return NULL;
}


int get_libdl_functions(struct runtime_info *rt_info)
{
    Elf32_Ehdr *ehdr = rt_info->libdl_start;
    Elf32_Shdr *shdr, *shdrs_start = (Elf32_Shdr *)(((char *)ehdr) + ehdr->e_shoff);
    Elf32_Sym *symbol, *symbols_start;
    char *strtab = get_dynstr_section(rt_info);
    int sec_it = 0, sym_it = 0;

    rt_info->dlopen = 0;
    rt_info->dlsym = 0;

    if(strtab == NULL)
        return -1;

    for(sec_it = 0; sec_it < ehdr->e_shnum; ++sec_it) {
        // Iterate over all sections to find .dynsym
        shdr = shdrs_start + sec_it;
        if(shdr->sh_type == SHT_DYNSYM)
        {
            // Ok we found the right section
            symbols_start = (Elf32_Sym *)(((char *)ehdr) + shdr->sh_offset);
            for(sym_it = 0; sym_it < shdr->sh_size / sizeof(Elf32_Sym); ++sym_it) {
                symbol = symbols_start + sym_it;
                unsigned char type = ELF32_ST_TYPE(symbol->st_info);
                unsigned char bind = ELF32_ST_BIND(symbol->st_info);
                unsigned int test = sizeof(Elf32_Sym);

                if(ELF32_ST_TYPE(symbol->st_info) != STT_FUNC)
                    continue;

                if(strncmp(strtab + symbol->st_name, DL_OPEN_NAME, sizeof DL_OPEN_NAME)) {
                    printf("Offset of dlopen: 0x%x\n", symbol->st_value);
                    rt_info->dlopen = ((char *)ehdr) + symbol->st_value;
                } else if(strncmp(strtab + symbol->st_name, DL_SYM_NAME, sizeof DL_SYM_NAME)) {
                    rt_info->dlsym = ((char *)ehdr) + symbol->st_value;
                }

                if(rt_info->dlopen != 0 && rt_info->dlsym != 0)
                    return 0;
            }
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
    
    for(it = 0; it <= n && s1[it] != '\0' && s2[it] != '\0'; it++) {
        if (s1[it] != s2[it])
            return 0;
    }

    if(it == n - 1 && s1[it] == '\0' && s2[it] == '\0')
        return 1;
    return 0;
}