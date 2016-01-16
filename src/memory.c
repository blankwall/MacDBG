#include "memory.h"

EXPORT
vm_offset_t read_memory(mach_port_t task, vm_address_t address, size_t size) {
    vm_offset_t buf;
    mach_msg_type_number_t sz;

    kern_return_t kret;
    kret = mach_vm_read(task, address, sizeof(char) *size, &buf, &sz);
    RETURN_ON_MACH_ERROR("[+read_memory] vm_read", kret);

    return buf;
}

EXPORT
mach_vm_address_t* read_memory_allocate(mach_port_t task, mach_vm_address_t address, size_t size) {
    kern_return_t kret;
    mach_vm_address_t *buf = safe_malloc(size);
    mach_vm_size_t nread = 0;

    kret = mach_vm_read_overwrite(task, address, size, (mach_vm_address_t)buf, &nread);
    RETURN_ON_MACH_ERROR("[+read_overwrite_memory] vm_read_overwrite", kret);

    return buf;
}

EXPORT
int write_memory(mach_port_t task, vm_address_t address, vm_offset_t data, mach_vm_size_t len) {
    kern_return_t kret;

    kret = mach_vm_write(task, address, (vm_offset_t)&data, len);
    RETURN_ON_MACH_ERROR("[+write_memory] vm_write", kret);

    return 1;
}

// ALLOCATES BUFFER AND PUTS CODE IN IT MAKING RWX
EXPORT
mach_vm_address_t inject_code(mach_port_t task, char *code, int length) {
    kern_return_t kret;
    mach_vm_address_t address = (vm_address_t) NULL;

    kret = mach_vm_allocate(task, &address, length, VM_FLAGS_ANYWHERE);
    RETURN_ON_MACH_ERROR("allocate", kret);

    int x = change_page_protection(task, address, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if(x == 0){
        printf("PAGE PROT FAILED\n");
        return 0;
    }

    kret = mach_vm_write(task, address, (vm_address_t)code, length);
    RETURN_ON_MACH_ERROR("write", kret);

    return address;
}

//WRITES DATA TO PREVIOUSLY ALLOCATED BUFFER
EXPORT
mach_vm_address_t write_bytes(mach_port_t task, mach_vm_address_t address, char *code, int length) {
    kern_return_t kret;

    kret = mach_vm_write(task, address, (vm_address_t)code, length);
    RETURN_ON_MACH_ERROR("write", kret);

    return address;
}

/*
 * Get base address of main image
 */
EXPORT
vm_address_t get_base_address(mach_port_t task) {
    kern_return_t kret;
    vm_region_basic_info_data_t info;
    vm_size_t size;
    mach_port_t object_name;
    mach_msg_type_number_t count;

    mach_vm_address_t address = 1;
    count = VM_REGION_BASIC_INFO_COUNT_64;
    kret = mach_vm_region(task, &address, (mach_vm_size_t*)&size, VM_REGION_BASIC_INFO, (vm_region_info_t)&info, &count, &object_name);

    RETURN_ON_MACH_ERROR("[+get_base_address] mach_vm_region", kret);

    return address;
}

EXPORT
kern_return_t change_page_protection(mach_port_t task, vm_address_t patch_addr, vm_prot_t new_protection) {
    kern_return_t kret;
    kret = mach_vm_protect(task, patch_addr, (mach_vm_size_t)4096, FALSE, new_protection);
    RETURN_ON_MACH_ERROR("change_page_protection\n", kret);
    return 1;
}

EXPORT
char* get_page_protection(mach_port_t task, vm_address_t patch_addr) {
    vm_region_basic_info_data_64_t *tmp =  get_region_info(task, patch_addr);
    char *x =  get_protection(tmp->protection);
    free(tmp);
    return x;
}

EXPORT
char* get_protection(vm_prot_t protection) {
    char *protect = safe_malloc(4);

    protect[0] = protection & 1 ? 'r' : '-';
    protect[1] = protection & (1 << 1) ? 'w' : '-';
    protect[2] = protection & (1 << 2) ? 'x' : '-';
    protect[3] = '\0';

    DEBUG_PRINT("PROTECTIONS: %s  %d %d %d\n", protect,VM_PROT_READ,VM_PROT_WRITE,VM_PROT_EXECUTE);
    return protect;
}

// MAYBE ADD WAY FOR USER TO SPECIFY
EXPORT
mach_vm_address_t* allocate(mach_port_t task, vm_address_t patch_addr, size_t size, int flags) {
    mach_vm_address_t *page_shared;
    kern_return_t kret;

    page_shared = safe_malloc(sizeof(mach_vm_address_t));

    *page_shared = patch_addr;

    kret = mach_vm_allocate(task, page_shared, size, flags);
    RETURN_ON_MACH_ERROR("[-allocate] mach_vm_allocate failed", kret);

    DEBUG_PRINT("[+allocate] Page Allocated %p\n", page_shared);
    return page_shared;
}

EXPORT
mach_vm_address_t allocate_space(mach_port_t task, size_t size, int flags) {
    kern_return_t kret;
    mach_vm_address_t patch_addr = NULL;

    kret = mach_vm_allocate(task, &patch_addr, size, flags);
    RETURN_ON_MACH_ERROR("[-allocate] mach_vm_allocate failed", kret);

    return patch_addr;
}

EXPORT
int free_memory(mach_port_t task, vm_address_t address, size_t size) {
    kern_return_t kret;

    kret = mach_vm_deallocate(task, address, size);
    RETURN_ON_MACH_ERROR("[-free_memory] mach_vm_deallocate failed", kret);
    DEBUG_PRINT("[+free_memory] memory from %lx of size %lu freed\n", address, size);

    return 1;
}

EXPORT
char* user_tag_to_string(unsigned int user_tag) {
      char *type;
      switch (user_tag) {
        case VM_MEMORY_MALLOC:          type="MALLOC";        break;
        case VM_MEMORY_MALLOC_TINY:     type="MALLOC_TINY";   break;
        case VM_MEMORY_MALLOC_SMALL:    type="MALLOC_SMALL";  break;
        case VM_MEMORY_MALLOC_LARGE:    type="MALLOC_LARGE";  break;
        case VM_MEMORY_MALLOC_HUGE:     type="MALLOC_HUGE";   break;
        case VM_MEMORY_REALLOC:         type="REALLOC";       break;
        case VM_MEMORY_SBRK:            type="SBRK";          break;
        case VM_MEMORY_ANALYSIS_TOOL:   type="ANALYSIS_TOOL"; break;
        case VM_MEMORY_MACH_MSG:        type="MACH_MSG";      break;
        case VM_MEMORY_IOKIT:           type="IOKit";         break;
        case VM_MEMORY_STACK:           type="STACK";         break;
        case VM_MEMORY_GUARD:           type="GUARD";         break;
        case VM_MEMORY_APPKIT:          type="APPKIT";        break;
        case VM_MEMORY_SHARED_PMAP:     type="SHARED_PMAP";   break;
        case VM_MEMORY_FOUNDATION:      type="FOUNDATION";    break;
        case VM_MEMORY_DYLIB:           type="DYLIB";         break;
        case VM_MEMORY_COREGRAPHICS:    type="CORE_GRAPHICS"; break;
        default:
          type="NULL";
    }
    return type;
}

EXPORT
vm_region_t** get_memory_map(mach_port_t task, mach_vm_address_t address, int *region) {
   // vm region top info parameters to retreive top info
    vm_region_top_info_data_t t_info;
    mach_msg_type_number_t t_count;
    mach_port_t t_object_name;
    mach_vm_size_t t_size;
    mach_vm_size_t size;
    vm_region_t **vm_region_list;

   // vm region recurse parameters to retreive submap info
    unsigned int depth;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count;

    mach_vm_address_t firstRegionBegin;
    mach_vm_address_t lastRegionEnd;
    vm_size_t fullSize;

    // vm region display parameters
    int flag = 0;
    int nregion = 0;
    char *type;
    int region_size;
    char *region_size_unit;
    char vprot[10];
    char *shrmod;
    char region_detail[PATH_MAX];

    // retrieve pid;
    pid_t infopid;
    pid_for_task(task, &infopid);

    kern_return_t kret;

    DEBUG_PRINT(" REGION TYPE\tADDRESS START\t ADDRESS END\t VSIZE\tPRT/MAX\t SHRMOD\tREGION DETAIL\t\t\n%d", '\x00');

    // vm region recurse should only be used, as submap only gives region type info
    // vm region top should only be used, as region top info only gives share mode info
    // proc_regionfilename should be queried for region detail

    t_count = VM_REGION_TOP_INFO_COUNT;
    count = VM_REGION_SUBMAP_INFO_COUNT_64;
    vm_region_list = safe_malloc(sizeof(vm_region_t) *MAX_REGION);
    depth = 0;
    fullSize = 0;

    while (flag == 0) {
        kret = mach_vm_region_recurse(task, &address, &size, &depth, (vm_region_info_t)&info, &count);
        if (kret == KERN_SUCCESS && nregion < MAX_REGION) {
            kret = mach_vm_region(task, &address, &t_size, VM_REGION_TOP_INFO, (vm_region_info_t)&t_info, &t_count, &t_object_name);

            if(kret==KERN_SUCCESS) {
                vm_region_t *vm_region=safe_malloc(sizeof(vm_region_t));

                type = user_tag_to_string(info.user_tag);

                region_size =size;

                if (region_size >=1024) { region_size /= 1024; region_size_unit = "K"; }
                if (region_size >=1024) { region_size /= 1024; region_size_unit = "M"; }
                if (region_size >=1024) { region_size /= 1024; region_size_unit = "G"; }

                if (nregion == 0) {
                    firstRegionBegin = address;
                }

                memset(vprot, 0, sizeof(vprot));    // reset vprot buf

                sprintf(vprot, "%c%c%c/%c%c%c\t",info.protection & VM_PROT_READ ? 'r' : '-',
                                                 info.protection & VM_PROT_WRITE ? 'w' : '-',
                                                 info.protection & VM_PROT_EXECUTE ? 'x' : '-',
                                                 info.max_protection & VM_PROT_READ ? 'r' : '-',
                                                 info.max_protection & VM_PROT_WRITE ? 'w' : '-',
                                                 info.max_protection & VM_PROT_EXECUTE ? 'x' : '-');

                switch(t_info.share_mode) {
                    case 1: shrmod="COW";  break;   // SM_COW
                    case 2: shrmod="PRV";  break;   // SM_PRIVATE
                    case 3: shrmod="NULL"; break;   // SM_EMPTY
                    case 4: shrmod="SHRD"; break;   // SM_SHARED
                    case 5: shrmod="TSHR"; break;   // SM_TRUESHARED
                    case 6: shrmod="P/A";  break;   // SM_PRIVATE_ALIASED
                    case 7: shrmod="S/A";  break;   // SM_SHARED_ALIASED
                    default: shrmod="???"; break;   // Not known
                }

                memset(region_detail, 0, sizeof(region_detail));    // reset region detail buf

                proc_regionfilename(infopid, address, region_detail, sizeof(region_detail));

                DEBUG_PRINT("USER TAG: %u\n", info.user_tag);
                vm_region->region_type    = info.user_tag;
                vm_region->address_start  = address;
                vm_region->address_end    = address+size;
                vm_region->size           = size;
                vm_region->protection     = info.protection;
                vm_region->max_protection = info.max_protection;
                vm_region->share_mode     = t_info.share_mode;

                strcpy(vm_region->region_detail,region_detail);

                // display similar to vmmap
                DEBUG_PRINT("%12s %016llx  %016llx %6d%s %8s SM=%s %s\n",
                       type,address,address+size,region_size,region_size_unit,vprot,shrmod,region_detail);

                vm_region_list[nregion]=vm_region;

                fullSize += size;
                address += size;
                nregion += 1;

            }
      }
      else{
         DEBUG_PRINT("ERROR %d\n", 1);
         flag = 1;
       }
   }
   lastRegionEnd = address;
//   printf("\n BASE ADDRESS: %llx END: %llx\n",firstRegionBegin, lastRegionEnd);
   *region = nregion;
   return vm_region_list;
}

static void catch_exc_segv() {
    longjmp(jbuf, 1);
}

EXPORT
dyld_info_struct** get_dyld_map(mach_port_t task, uint32_t *no_of_dyld ) {

    struct task_dyld_info dyld_info;

    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;

    if (task_info(task, TASK_DYLD_INFO, (task_info_t) &dyld_info, &count) == KERN_SUCCESS) {

        mach_msg_type_number_t size = sizeof(struct dyld_all_image_infos);
        uint8_t *data = (uint8_t*) read_memory(task, dyld_info.all_image_info_addr, size);
        struct dyld_all_image_infos *infos = (struct dyld_all_image_infos *) data;
        mach_msg_type_number_t size2 = sizeof(struct dyld_image_info)  *infos->infoArrayCount;
        uint8_t *info_addr = (uint8_t*) read_memory(task, (mach_vm_address_t) infos->infoArray, size2);
        struct dyld_image_info *info = (struct dyld_image_info*) info_addr;
        dyld_all_infos_struct *dyld_all_infos = safe_malloc(sizeof(dyld_all_infos_struct));
        dyld_all_infos->dyld=safe_malloc(sizeof(dyld_info_struct *)  *MAX_NO);
        dyld_all_infos->count = 0;
        dyld_info_struct *new_dyld_info;
        library_all_infos_struct *map_infos = ReadSharedCacheMap(DYLD_CACHE_MAP);

        for (int i=0; i < infos->infoArrayCount; i++) {

            vm_offset_t psize = 255; //having PATH_MAX i.e 1024 returns null for the first shared region
            char *fpath_addr = (char*) read_memory(task,(mach_vm_address_t) info[i].imageFilePath, psize);
            if (fpath_addr) {
                mach_vm_address_t image_base_addr = (mach_vm_address_t)info[i].imageLoadAddress;
                const struct mach_header_64 *header = (struct mach_header_64 *)(image_base_addr);
                uint8_t *header_ptr = (uint8_t*)header + sizeof(*header);
                signal(SIGSEGV, catch_exc_segv);
                struct load_command *lc = (struct load_command *) (header_ptr);

                if (setjmp (jbuf)!=0) {
                    // Ouch! I crashed!
                    //crashes as application memory can only be accessed via mach_vm_read

                    size_t sz=4;                //no of bytes to read
                    size_t off_ncmds = 16;      //offset for no of commands from mach header
                    size_t off_segname = 8;     //ofset for segment name from load command header
                    size_t off_cmdsize= 4;      //ofset for command size from load command header
                    size_t off_vmsize = 32;     //ofset for vm size from load command header
                    size_t off_initprot = 60;   //offset for init prot from load command header

                    vm_offset_t *no_of_cmds = (vm_offset_t*)read_memory(task, (vm_address_t)((uint8_t*)header+off_ncmds), sz);
                    mach_vm_address_t lc_ptr = (mach_vm_address_t)lc;
                    mach_vm_address_t data_start_addr=0;

                    for (uint32_t j=0; j<(*no_of_cmds);j++) {

                        vm_offset_t *seg_code = (vm_offset_t*)read_memory(task, lc_ptr, sz);
                        if(*seg_code == LC_SEGMENT_64) {
                            char *seg_name = (char*)read_memory(task, (vm_address_t)((uint8_t*)lc_ptr+off_segname), 10);
                            if(strcmp(seg_name, "__PAGEZERO")==0) {
                                vm_offset_t *pz_csz = (vm_offset_t*)read_memory(task, (vm_address_t)((uint8_t*)lc+off_cmdsize), sz);
                                lc_ptr = (mach_vm_address_t)((uint8_t*)lc_ptr+(*pz_csz));

                            }
                            else if(strcmp(seg_name, "__TEXT")==0) {
                                vm_offset_t *txt_size = (vm_offset_t*)read_memory(task, (vm_address_t)((uint8_t*)lc_ptr+off_vmsize), sz);

                                new_dyld_info =  safe_malloc(sizeof(dyld_info_struct));
                                new_dyld_info->fpath = fpath_addr;
                                new_dyld_info->start_address = image_base_addr;
                                new_dyld_info->end_address = (mach_vm_address_t)((uint8_t*)image_base_addr+(*txt_size));
                                new_dyld_info->type = __TEXT;
                                new_dyld_info->size = *txt_size;
                                new_dyld_info->protection = (int*)read_memory(task, (vm_address_t)((uint8_t*)lc_ptr+off_initprot), sz);;

                                dyld_all_infos->dyld[dyld_all_infos->count++] = new_dyld_info;

                                data_start_addr= new_dyld_info->end_address;

                                vm_offset_t *txt_csz = (vm_offset_t*)read_memory(task, (vm_address_t)((uint8_t*)lc_ptr+off_cmdsize), sz);
                                lc_ptr = (mach_vm_address_t)((uint8_t*)lc_ptr+ (*txt_csz));
                            }
                            else if(strcmp(seg_name, "__DATA")==0) {

                                vm_offset_t *data_size = (vm_offset_t*)read_memory(task,(vm_address_t)((uint8_t*)lc_ptr+off_vmsize), sz);

                                new_dyld_info =  safe_malloc(sizeof(dyld_info_struct));
                                new_dyld_info->fpath = fpath_addr;
                                new_dyld_info->start_address = data_start_addr;
                                new_dyld_info->end_address = (mach_vm_address_t)((uint8_t*)new_dyld_info->start_address+(*data_size));
                                new_dyld_info->size = *data_size;
                                new_dyld_info->type = __DATA;
                                new_dyld_info->protection = (int*)read_memory(task, (vm_address_t)((uint8_t*)lc_ptr+off_initprot), sz);;

                                dyld_all_infos->dyld[dyld_all_infos->count++] = new_dyld_info;

                                vm_offset_t *data_cmz = (vm_offset_t*)read_memory(task, (vm_address_t)((uint8_t*)lc_ptr+off_cmdsize), sz);
                                lc_ptr = (mach_vm_address_t)((uint8_t*)lc_ptr+ (*data_cmz));

                                break; //as we are not interested in other load commands
                            }
                            else if(strcmp(seg_name, "__LINKEDIT")==0) {
                                break; //as we are not interested in load commands other than __DATA & __TEXT
                            }
                        }
                    }
                    continue;

                }

                for (uint32_t i = 0; i < header->ncmds; i++) {
                    if (lc->cmd == LC_SEGMENT_64) {
                        if (strcmp(((struct segment_command_64 *)lc)->segname, "__TEXT") == 0)
                        {
                            size_t sz=((struct segment_command_64 *) lc)->vmsize; // Size of segments

                            new_dyld_info =  safe_malloc(sizeof(dyld_info_struct));
                            new_dyld_info->size = sz;
                            new_dyld_info->type = __TEXT;
                            new_dyld_info->fpath = fpath_addr;
                            new_dyld_info->start_address = image_base_addr;
                            new_dyld_info->end_address = (mach_vm_address_t)((uint8_t*)image_base_addr+sz);
                            new_dyld_info->protection = ((struct segment_command_64 *)lc)->initprot;

                            dyld_all_infos->dyld[dyld_all_infos->count++] = new_dyld_info;
                        }
                        else if (strcmp(((struct segment_command_64 *)lc)->segname, "__DATA") == 0)
                        {
                            size_t sz=((struct segment_command_64 *) lc)->vmsize; // Size of segments
                            new_dyld_info =  safe_malloc(sizeof(dyld_info_struct));
                            dyld_map *map_info = find_dyld_map(map_infos, fpath_addr);
                            if(map_info) {
                                uint8_t *dataLoadAaddress = (uint8_t*)image_base_addr -
                                                (map_info->image_start_address-map_info->data_start_address);

                                new_dyld_info->start_address = (mach_vm_address_t)(dataLoadAaddress);
                                new_dyld_info->end_address = (mach_vm_address_t)((uint8_t*)dataLoadAaddress+sz);
                                new_dyld_info->protection = ((struct segment_command_64 *)lc)->initprot;

                            }
                            else {
                                new_dyld_info->start_address = '\0';
                                new_dyld_info->end_address = '\0';
                                new_dyld_info->protection = '\0';

                            }

                            new_dyld_info->size = sz;
                            new_dyld_info->type = __DATA;
                            new_dyld_info->fpath = fpath_addr;

                            dyld_all_infos->dyld[dyld_all_infos->count++] = new_dyld_info;

                        }

                    }

                    lc = (struct load_command *) ((char *) lc + lc->cmdsize);

                }

            }
        }
#if DEBUG
        for (uint32_t i=0;i<dyld_all_infos->count;i++) {
            dyld_info_struct *dyldinfo = dyld_all_infos->dyld[i];
            char *type[] = {"__TEXT", "__DATA"};
            printf("%s %llx %llx %luk %s\n", type[dyldinfo->type], dyldinfo->start_address, dyldinfo->end_address, dyldinfo->size/1024, dyldinfo->fpath);
        }
#endif
        // for(int i=0;i<map_infos->count;i++)
        //     free(map_infos->lib_info[i]);
        // free(map_infos);

        *no_of_dyld =  dyld_all_infos->count;

        return dyld_all_infos->dyld;
    }
    *no_of_dyld =0;

    fprintf(stderr, "ERROR IN DYLD MAP EXITING\n");
    exit(1);
    return NULL;
}

EXPORT
vm_region_basic_info_data_64_t* get_region_info(mach_port_t task, mach_vm_address_t address) {
    mach_port_t object_name;
    mach_vm_size_t size_info;
    mach_vm_address_t address_info = address;
    kern_return_t kret = 0;
    vm_region_basic_info_data_64_t *info = safe_malloc(sizeof(vm_region_basic_info_data_64_t));
    mach_msg_type_number_t info_cnt = sizeof(vm_region_basic_info_data_64_t);

    kret = mach_vm_region(task, &address_info, &size_info, VM_REGION_BASIC_INFO_64, (vm_region_info_t)info, &info_cnt, &object_name);
    RETURN_ON_MACH_ERROR("[-get_region_info] mach_vm_region", kret);

    return info;
}

EXPORT
uint64_t get_image_size(mach_port_t task, mach_vm_address_t address)
{
    int i;
    unsigned char *cmd_addr = 0;
    unsigned char *cmds = 0;
    uint64_t imagefilesize = 0;
    struct load_command* loadCommand    = NULL;
    struct segment_command_64 *seg_cmd = NULL;

    struct mach_header *head = read_memory_allocate(task,address, sizeof(struct mach_header));
    if (head->magic != MH_MAGIC_64) {
        return 0;
    }

    cmds = read_memory_allocate(task,  address+sizeof(struct mach_header_64), head->sizeofcmds);

    cmd_addr = cmds;
    for (i = 0; i < head->ncmds; i++){
        loadCommand = cmd_addr;
         if (loadCommand->cmd == LC_SEGMENT_64) {
            seg_cmd = cmd_addr;
            if (strncmp(seg_cmd->segname, "__PAGEZERO", 16) != 0) {
                imagefilesize += seg_cmd->filesize;
            }
        }
        cmd_addr += loadCommand->cmdsize;
    }
    free(cmds);

    return imagefilesize;
}
