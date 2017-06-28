#include <linux/module.h>
#include <linux/kernel.h>

#include <data_copy.h>
#include <data.h>
#include <utils.h>


void loadsegms(void);


void loadmodtab(void);


void loadfuntab(void);


void loadthdtab(void);


void loadinitab(void);

void loadblks(void) {
    int it;
    char    blknam[16] = {0};                               // block ID name
    BYTE    *blkptr;                                        // block pointer to shared region
    uint    blksz;                                          // block size
    

    for(it = 0; i < ctl_region->nblks; ++it) { // Each block gets its own shared region
        printk(KERN_INFO "[+] Loading block #%d... ", i+1 );
        
        sprintf_s(blknam, 16, "%d", i+1 );                  // convert ID to string

        blksz  = blklen[i];                                 // get block size
        blkptr = crtshreg(blknam, blksz);                   // create shared region

        memcpy(blkptr, supblk[i], blksz );

        if( *(ushort*)(blkptr + 4) < MAXNBLKS )             // overflow?
            strcpy_s(shctrl->blk[*(ushort*)(blkptr+4) ].name, 8, blknam);
        else fatal("Overflow detected in block #%d", i);

        printf( "Done.\n" );
    }
}