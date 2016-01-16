#ifndef M_H
#define M_H
#include <libproc.h>
#include <mach-o/dyld_images.h>
#include <setjmp.h>
#include <mach-o/loader.h>
#include "mcdb.h"

#define MAX_REGION 100

static jmp_buf jbuf;

typedef enum  {__TEXT, __DATA} region_type;

#define MAX_NO 2048

#define DYLD_CACHE_MAP "/var/db/dyld/dyld_shared_cache_x86_64h.map"

#define MAX_REGION 100

typedef struct vm_region_info{
    unsigned int region_type;
    mach_vm_address_t address_start;
    mach_vm_address_t address_end;
    mach_vm_size_t size;
    unsigned int protection;
    unsigned int max_protection;
    unsigned int share_mode;
    char region_detail[PATH_MAX]; //it could be a path to loaded library or other info about the region
}vm_region_t;

typedef struct {
    mach_vm_address_t start_address;
    mach_vm_address_t end_address;
    region_type type;
    size_t size;
    char *fpath;
    unsigned int protection;
    //todo prot, moddate
}dyld_info_struct;

typedef struct {
    dyld_info_struct **dyld;
    unsigned int count;
}dyld_all_infos_struct;


vm_offset_t read_memory(mach_port_t task, vm_address_t address, size_t size);
int write_memory(mach_port_t task, vm_address_t address, vm_offset_t data, mach_vm_size_t len);
mach_vm_address_t* read_memory_allocate(mach_port_t task, mach_vm_address_t address, size_t size);
vm_address_t get_base_address(mach_port_t task);
char* get_protection(vm_prot_t protection);
kern_return_t change_page_protection(mach_port_t task, vm_address_t patch_addr, vm_prot_t new_protection);
mach_vm_address_t* allocate(mach_port_t task, vm_address_t patch_addr, size_t size, int flags);
int free_memory(mach_port_t task, vm_address_t address, size_t size);
vm_region_t** get_memory_map(mach_port_t task, mach_vm_address_t address, int* region);
dyld_info_struct** get_dyld_map(mach_port_t task, uint32_t *no_of_dyld);
vm_region_basic_info_data_64_t* get_region_info(mach_port_t task, mach_vm_address_t address);
char* user_tag_to_string(unsigned int user_tag);
char* get_page_protection(mach_port_t task, vm_address_t patch_addr);
mach_vm_address_t allocate_space(mach_port_t task, size_t size, int flags);
mach_vm_address_t inject_code(mach_port_t task, char* code, int length);
mach_vm_address_t write_bytes(mach_port_t task, mach_vm_address_t address, char* code, int length);
uint64_t get_image_size(mach_port_t task, mach_vm_address_t address);
#endif
