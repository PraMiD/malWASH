#ifndef _UTILS_H
#define _UTILS_H
/**
 *  This module provides helper methods for all parts of the kernel module.
 *  In addition, we store publicly available data here, eg the shared regions.
 */

/*  DEFINES */
#define FUNTBLSIZE      4096                                // max function table size
#define SEGMTABSIZE     32                                  // segment table size 
#define MAXNBLKS        1536                                // max number of blocks (they'll be many in paranoid mode)
#define MAXSEGNAMELEN   64                                  // max segment name length
#define MAXBLKSIZE      768                                 // max block size
#define MAXMODNAMELEN   64                                  // max imported module name length
#define MODTABSIZE      32                                  // module table size
#define MAXCONCURNPROC  16                                  // max number of injected processes ??
#define MAXOPENHANDLE   8                                   // max number of concurrent open SOCKETs/HANDLEs
#define MAILBOXSIZE     1024                                // mailbox size (1K is fine)
#define MAXMAILBOXSIZE  8                                   // maximum number of unread mails
#define STACKBASEADDR   0x19900000                          // stack virtual base address
#define STACKSIZE       0x20000                             // stack size
#define STACKBASEADDR2  0x19900040                          // different call caches for different dependencies
#define SEGMBASEADDR    0x1bb00000                          // 1st segment virtual base address
#define SEGMNXTOFF      0x20000                             // virtual offset between segment base address
#define HEAPBASEADDR    0x1cc00000                          // heap starts from here
#define NMAXTHREADS     4                                   // maximum number of threads that we can handle
#define ARGVBASEOFF     0x200                               // base address of argv table
#define ARGVPTRBASEOFF  0x240                               // base address of argv pointers 
#define ARGVNXTOFF      0x40                                // offset between argv pointers
#define THREAD_UNUSED   0xffff                              // thread does not exists
#define THREAD_RUNNING  0x0001                              // thread is running
#define CMD_WSASTARTUP  0x01  

/*  DATA    */
extern struct shrd_region_struct ctl_region_handle;
extern struct ctl_reg_t *ctl_reg;
extern size_t ctl_region_size;


/*  STRUCTS  */
struct ctl_reg_t 
{
    // ----------------------------------------------------------------------------------
    unsigned short reserved1,                                      // reserved
                   nblks,                                          // total number of blocks
                   nsegms,                                         // total number of segments
                   nmods,                                          // total number of modules
                   funtabsz,                                       // function table size
                   nproc;                                          // number of injected proccesses
    unsigned long nxtheapaddr;                                     // next address in heap to allocate
    unsigned short nxtblk[NMAXTHREADS],                            // next block to execute (1 per thread)
                   thrdst[NMAXTHREADS];                            // thread states    
    unsigned long  thrdrtn[NMAXTHREADS];                           // thread entry points
            
    char    spin;                                                   // spin flag
    char    reserved2[7];                                           // reserved for future use
    // ----------------------------------------------------------------------------------
    struct context_t {                                              // context switch struct (0x28 bytes)
        unsigned int eax,                                           // we store 8 basic registers + FLAGS
                     edx,                                           //
                     ecx,                                           //
                     ebx,                                           //
                     esi,                                           //
                     edi,                                           //
                     esp,                                           //
                     ebp,                                           // don't need eip
                     eflags,                                        //
                     reserved;                                      // reserved for future use
        char stack[STACKSIZE];                                      // Memory for a shared stack for each thread
    } 
    ctx[NMAXTHREADS];                                               // context variable
    // ----------------------------------------------------------------------------------
    struct segm_t {                                                 // segments information (0x10 bytes)
        unsigned short segmid;                                      // segment id (optional, as segments are
                                                                    // sequential starting from 0)
        char name[6];                                               // random name to identify shared region
        void *startEA, *endEA;                                      // start and end RVAs
        int offset;                                                 // All segments are stored directly
                                                                    // in the control region. Store the offset of
                                                                    // each segment in the control region
    } 
    segm[SEGMTABSIZE];                                              // store segments in an array
    // ----------------------------------------------------------------------------------
    struct modl_t {                                                 // module information
                                                                    // module id is used as an index
        char name[MAXMODNAMELEN];                                   // module name
    } 
    modl[MODTABSIZE];                                               // store modules here
    // ----------------------------------------------------------------------------------
    struct blk_t {                                                  // basic block information
                                                                    // bid is used as index
        char name[8];                                               // random name to identify shared region
        int offset;                                                 // Store the offset of this block in the 
                                                                    // control region. See offset in segm_t!
    }
    blk[MAXNBLKS];                                                  // store bid shared region names here
    // ----------------------------------------------------------------------------------
    char funtab[ FUNTBLSIZE ];                                      // function table
    char reserved3[ 8 ];                                            // reserved for future use
    // ----------------------------------------------------------------------------------
    unsigned long pidtab[MAXCONCURNPROC];                           // table of all loaded pids
    // ----------------------------------------------------------------------------------
    struct duptab_entry {                                           // duplication table entry (72 bytes)
        unsigned long origval;                                      // original value of SOCKET/HANDLE
        unsigned short type;                                        // HANDLE or SOCKET?
        unsigned short reserved3;                                   // for future use
        void *handle[ MAXCONCURNPROC ];                             // SOCKET/HANDLE value
    } 
    duptab[MAXOPENHANDLE];                                          // every open SOCKET/HANDLE has 1 entry
    // ----------------------------------------------------------------------------------
    struct mailbox_t {                                              // mailbox data type (1024 bytes)
        unsigned short cmd,                                         // message command
                reserved;                                           // reserved value
        void *handle;                                               // original SOCKET/HANDLE value
        unsigned long reserved2[2];                                 // another reserved value       
        
        char data[MAILBOXSIZE - 16];                                // message data
    }
    mailbox[MAXCONCURNPROC][MAXMAILBOXSIZE];                        // 1 mailbox for each process
    // ----------------------------------------------------------------------------------
};


/*  FUNCTIONS   */
void reasm(void);
#endif