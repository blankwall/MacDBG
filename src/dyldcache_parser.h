#ifndef DC_H
#define DC_H

#include "mcdb.h"

#define MAXINDEX 2040

#define TEXT_R      0
#define DATA_R      1
#define OBJC_R      2
#define IMPORT_R    3
#define UNICODE_R   4
#define IMAGE_R     5
#define LINKEDIT_R  6

typedef struct {
    uint64_t b_address;
    uint64_t e_address;
    int     r_type;
    char     *name;
}library_info_struct;

typedef struct {
    library_info_struct *lib_info[MAXINDEX];
    unsigned int count;
}library_all_infos_struct;

typedef struct {
    char* name;
    mach_vm_address_t image_start_address;
    mach_vm_address_t image_end_address;
    mach_vm_address_t data_start_address;
    mach_vm_address_t data_end_address;
}dyld_map;

int scanline(char *inputstring, char **argv, int maxtokens);
library_all_infos_struct* ReadSharedCacheMap(const char *path);
dyld_map* find_dyld_map(library_all_infos_struct* dyld_infos, char *dylib_path);

#endif
