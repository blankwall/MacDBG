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
Generic test showing off how to threads
*/


int generic_callback(exc_msg_t *info_struct){
    printf("\nBREAKPOINT CALLBACK %p\n", info_struct->code);
    // getchar();
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
    pid_t infoPid;
    kern_return_t kret;
    mach_port_t task, server_port;
    thread_act_port_array_t threadList;
    mach_msg_type_number_t threadCount;
    x86_thread_state64_t *state;

    if(argc < 2) {
        puts("Usage: sudo ./debugger [pid]");
        exit(-1);
    }

    infoPid = atoi(argv[1]);

    task = attach(infoPid);
    long xen = get_base_address(task);

    int xeny = 0xf1e;

    void* x = allocate(task, 0,   4096, 1);

    for(int i = 0; i < 10000000; i += 4096) {
        change_page_protection(task, xen, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
        xen += i;
    }

    mach_vm_address_t k = get_base_address(task) + xeny;

    printf("READ MEMORY TEST: %lu\n", read_memory(task, k, 4));
    printf("READ MEMORY OVERWRITE TEST: %llu\n", (unsigned long long)read_memory_allocate(task, k, 4));

    free_memory(task, (mach_vm_address_t)x, 4096); //free the allocated memory

    state = thread_state(task, 0);
    mach_vm_address_t base_addr = get_base_address(task);

//    printf("BASE ADDRESS1: %llx\n", base_addr);

    vm_region_t *vm_region_list[MAX_REGION];

    // get_memory_map(task, base_addr, vm_region_list);

    // vm_region_basic_info_data_64_t* region_info= NULL;
    // region_info = get_region_info(task, xen);
    // printf("PROTECTIONS OF REGION ARE: %s\n", get_protection(region_info->protection));

    mach_vm_address_t patch_addr = base_addr+0xc70;

    add_breakpoint(task, patch_addr, PERSISTENT, generic_callback);
    // add_breakpoint(task, base_addr+0xe0e, PERSISTENT, generic_callback);
    // add_breakpoint(task, base_addr+0xe3a, PERSISTENT, generic_callback);
    list_breaks(task);

    add_exception_callback(task, generic_callback_9, EXC_BAD_ACCESS);

    //tracking process creation
    add_exception_callback(task, generic_callback_3, NOTE_EXEC);
    add_exception_callback(task, generic_callback_2, NOTE_FORK);
    add_exception_callback(task, generic_callback_5, NOTE_SIGNAL);
    add_exception_callback(task, generic_callback_4, NOTE_EXIT);

    // thread_act_port_array_t* list_threads = thread_list(task);
    // mach_msg_type_number_t tc = thread_count(task);
    // printf("THREADS: %d\n", tc);

    thread_array_t thread_list;
    mach_msg_type_number_t tc;
    thread_list_info(task, &thread_list, &tc);
    printf("THREADS: %d\n", tc);


    continue_(task);
    sleep(1);

    int i;
    int verbose = 1;
    int wordsize = 8;
    for(i = 0; i < tc; i++){

        //DEFINED HERE http://www.opensource.apple.com/source/xnu/xnu-1456.1.26/osfmk/mach/thread_info.h
        thread_basic_info_t basic_info = get_thread_basic_info (thread_list[i]);
        thread_identifier_info_data_t identifier_info = get_thread_identifier_info (thread_list[i]);

          int wordsize;
          state = thread_state(task, i);
          uint64_t pc = state->__rip;

          printf ("thread #%d, system-wide-unique-tid %lld, suspend count is %d, ", i,
                  identifier_info.thread_id,
                  basic_info->suspend_count);
        
          printf ("pc 0x%016llx, ", pc);

          printf ("run state is ");
          switch (basic_info->run_state) {
            case TH_STATE_RUNNING: puts ("running"); break;
            case TH_STATE_STOPPED: puts ("stopped"); break;
            case TH_STATE_WAITING: puts ("waiting"); break;
            case TH_STATE_UNINTERRUPTIBLE: puts ("uninterruptible"); break;
            case TH_STATE_HALTED: puts ("halted"); break;
            default: puts ("");
          }

          printf ("           pthread handle id 0x%llx (not the same value as pthread_self() returns)\n", (uint64_t) identifier_info.thread_handle);

 

          free ((void *) basic_info);
    }

    // start(task, infoPid);
    // while(1);
    sleep(10);
    detach(task);

    return 0;
}
