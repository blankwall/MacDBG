#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <mach/mach_types.h>
#include <mach/mach_traps.h>
#include <limits.h>
#include <mach/boolean.h>
#include <mach/error.h>
#include <mach/mach_error.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <mach/mach.h>
#include <errno.h>
#include <mach/mach_vm.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <pthread.h>
#include "../mcdb.h"

/*
Generic test showing off how to use some of the features
*/
int generic_callback_44(exc_msg_t *info_struct){
    printf("\nMALCALLBACK\n");
    getchar();
    return 1;
}


int generic_callback(exc_msg_t *info_struct){
    x86_thread_state64_t* state = get_state(info_struct->thread);
    char*k = read_memory(info_struct->task, state->__rsp, 8);
    printf("MALLOC CALLED SIZE: %llx\t", state->__rdi);
    printf("%llx\n", k);
    return 1;
}
int generic_callback_2(exc_msg_t *info_struct){
    printf("\nFORK CALLBACK\n");
    getchar();
    return 1;
}
int generic_callback_3(exc_msg_t *info_struct){
    printf("\nEXEC CALLBACK\n");
    getchar();
    return 1;
}
int generic_callback_4(exc_msg_t *info_struct){
    printf("\nEXIT CALLBACK\n");
    exit(-1);
}
int generic_callback_5(exc_msg_t *info_struct){
    printf("\nSIGNAL CALLBACK\n");
    getchar();
    return 1;
}
int generic_callback_9(exc_msg_t *info_struct){
    printf("OMG A CRASH CALLBACK\n");
    getchar();
    task_terminate(info_struct->task);
    exit(-1);
}


int main(int argc, char** argv){
    mach_port_t task;
    pid_t infoPid;
    //kern_return_t kret;
    //thread_act_port_array_t threadList;
    //mach_msg_type_number_t threadCount;
    x86_thread_state64_t *state;
    vm_region_basic_info_data_64_t* region_info= NULL;


    if(argc < 2) {
        puts("Usage: sudo ./debugger [pid]");
        exit(-1);
    }
     unsigned char shellcode[] =
    "\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41";


    infoPid = atoi(argv[1]);
    task = attach(infoPid);

    mach_vm_address_t xello = inject_code(task, shellcode, strlen(shellcode));
    printf("CODE INJECTED @ %p\n", xello);
    
    long xen = get_base_address(task);


    printf("%lld\n", get_image_size(task, xen));

    mach_vm_address_t patch_addr = allocate_space(task, 4000, VM_FLAGS_ANYWHERE);

    char* code = "hello";

    int xe = change_page_protection(task, patch_addr, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if(xe == 0){
        printf("PAGE PROT FAILED 2\n");
    } else {
        printf("PAGE PROT SUCCESS \n");
    }

    printf("PAGE ALLOCATED @ %p\n WRITING HELLO!\n", patch_addr);
    write_bytes(task, patch_addr, "hello", 5);

    char* xop = read_memory(task, patch_addr, 20);
    printf("XOP (%p)\n", xop);

    print_byte(xop);


    // print_byte(xop);

    printf("READING THE HEADER: ");
    print_byte(read_memory(task, xen, 20));


    int xeny = 0xf1e;

    void* x = allocate(task, 0,   4096, 1);
    //Should fail
    void* N = allocate(task, 0,   9999999999999999999, 1);


    region_info = get_region_info(task, x);
    printf("ALLOCATED PROTECTIONS OF REGION ARE: %s\n", get_page_protection(task, x));


    for(int i = 0; i < 10000000; i += 4096) {
        change_page_protection(task, xen, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        xen += i;
    }



    mach_vm_address_t k = get_base_address(task) + xeny;

    printf("READ MEMORY TEST: %s\n", read_memory(task, k, 4));
    printf("READ MEMORY OVERWRITE TEST: %s\n", (unsigned long long)read_memory_allocate(task, k, 4));

    free_memory(task, (mach_vm_address_t)x, 4096); //free the allocated memory

    state = thread_state(task, 0);
    mach_vm_address_t base_addr = get_base_address(task);

//    printf("BASE ADDRESS1: %llx\n", base_addr);

    // vm_region_t *vm_region_list[MAX_REGION];

    int regions;
    vm_region_t ** vm_region_list = get_memory_map(task, base_addr, &regions);
    vm_region_t* vm_region_1 = vm_region_list[0];
    printf("# of Regions == %d -- FIRST REGION INFO: \n", regions);

     printf("TYPE:%s BASE ADDRESS: 0x%016llx  END ADDRESS: 0x%016llx SIZE: 0x%llx PROT:%s\n",
                       user_tag_to_string(vm_region_1->region_type) ,vm_region_1->address_start,
                       vm_region_1->address_start+vm_region_1->size,vm_region_1->size,
                       get_protection(vm_region_1->protection));


    region_info = get_region_info(task, xen);
    printf("PROTECTIONS OF REGION ARE: %s\n", get_protection(region_info->protection));

    printf("PROTECTIONS FOR BASE_ADDR ARE: %s\n",  get_page_protection(task, base_addr));

    uint32_t no_dyld;
    dyld_info_struct **infos = get_dyld_map(task, &no_dyld);
    const char* region[]={"__TEXT", "__DATA"};

    for (uint32_t i=0;i< no_dyld; i++){
        dyld_info_struct *dyldinfo = infos[i];
        // if (dyldinfo->start_address == base_addr) {
            printf("%s %llx %llx %luk %s %s\n", region[dyldinfo->type], dyldinfo->start_address, 
                dyldinfo->end_address, dyldinfo->size/1024,
             dyldinfo->fpath, get_protection(dyldinfo->protection));
            break;
        // }
    }

    printf("# of Regions == %d -- # of  dyld's: %d\n", regions, no_dyld);


    patch_addr = base_addr+0xd90;

    add_breakpoint(task, patch_addr, ONE_TIME, generic_callback);
    add_breakpoint(task, base_addr+0xe0e, PERSISTENT, generic_callback);
    add_breakpoint(task, base_addr+0xe3a, PERSISTENT, generic_callback);
    // list_breaks(task);

    add_exception_callback(task, generic_callback_9, EXC_BAD_ACCESS);

    //tracking process creation
    add_exception_callback(task, generic_callback_3, NOTE_EXEC);
    add_exception_callback(task, generic_callback_2, NOTE_FORK);
    add_exception_callback(task, generic_callback_5, NOTE_SIGNAL);
    add_exception_callback(task, generic_callback_4, NOTE_EXIT);

    thread_array_t thread_list;
    mach_msg_type_number_t tc;
    thread_list_info(task, &thread_list, &tc);

    // printf("THREADS: %d\n", tc);
    thread_identifier_info_data_t* identifier_info = get_thread_identifier_info (thread_list[0]);
    thread_basic_info_t basic_info = get_thread_basic_info (thread_list[0]);


    fprintf(stderr, "TID: %llu\n", identifier_info->thread_id);
    printf("USER TIME: %d\n", basic_info->user_time.seconds);


    continue_(task);
    sleep(10);
    detach(task);
    task = attach(infoPid);
    if(task != 0){
        printf("REATTACHED SUCCESFULLY!\n");
    }
    exit(1);
    return 0;
}

