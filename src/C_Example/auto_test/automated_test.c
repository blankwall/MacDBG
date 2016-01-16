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
#include "../../mcdb.h"
#include "../../memory.h"

int crash_ = 0;
int exec_ = 0;
int fork_ = 0;
int signal_ = 0;
int exit_ = 0;
int breaks_ = 0;
int reg_change = 0;
int allocate_ = 0;
int free_ =0;
int base_ = 0;
int state_ = 0;
int protect_ = 0;

int generic_callback_2(exc_msg_t *info_struct) {
    fprintf(stderr, "\nFORK CALLBACK\n");
    fork_ = 1;
    // getchar();
    return 1;
}

int generic_callback_3(exc_msg_t *info_struct) {
    exec_ = 1;
    // getchar();
    return 1;
}

int generic_callback_4(exc_msg_t *info_struct) {
    exit_ = 1;
    exit(-1);
}

int generic_callback_5(exc_msg_t *info_struct) {
    signal_ = 1;
    // getchar();
    return 1;
}

int generic_callback(exc_msg_t *info_struct) {
    printf("\nBREAKPOINT CALLBACK %p\n", info_struct->code);
    x86_thread_state64_t *break_state = get_state(info_struct->thread);
    // enumerate_reg_simple(break_state);
    mach_vm_address_t x = break_state->__rip & 0xfff;

    breaks_ += 1;
    //FUNCTION OFFSETS MAY NEED TO BE CHANGED
    if(x == 0xd20) {
        reg_change += 1;
        break_state->__rsi = 99;
        // break_state->__rip &= 0xffffff000;
        // break_state->__rip += 0xd70;


                              // 0x101117d50
        set_thread_state(info_struct->thread, break_state);
        // printf("IN FUNCTION!\n");
    }
    // getchar();
    return 1;
}

int generic_callback_9(exc_msg_t *info_struct) {
    mach_port_t task = info_struct->task;
    long xen = get_base_address(task);
    int xeny = 0xF22;
    mach_vm_address_t k = xen + xeny;
    fprintf(stderr, "\nTEST COMPLETE\nRESULTS:\n");

    if(strncmp((const char *)read_memory(task, k, 4), "blue", 4)) {
        fprintf(stderr, "FAILED [read_memory]\n");
    } else {
        fprintf(stderr, "PASSED [read_memory]\n");
    }

    if(strncmp((const char *)read_memory_allocate(task, k, 4), "blue", 4)) {
        fprintf(stderr, "FAILED [read_memory_allocate]\n");
    } else {
        fprintf(stderr, "PASSED [read_memory_allocate]\n");
    }

    if(!(fork_ & 1)) {
        fprintf(stderr, "FAILED [fork]\n");
    } else {
        fprintf(stderr, "PASSED [fork]\n");
    }

    if(!(signal_ & 1)) {
        fprintf(stderr, "FAILED [signal]\n");
    } else {
        fprintf(stderr, "PASSED [signal]\n");
    }

    if(breaks_ != 5 || reg_change != 4) {
        fprintf(stderr, "FAILED [breakpoints]\n");
    } else {
        fprintf(stderr, "PASSED [breakpoints]\n");
    }

    if(!(allocate_ & 1)) {
        fprintf(stderr, "FAILED [allocate] \n");
    } else {
        fprintf(stderr, "PASSED [allocate_]\n");
    }

    if(!(base_&1)) {
        fprintf(stderr, "FAILED [base_addr]\n");
    } else {
        fprintf(stderr, "PASSED [base_addr]\n");
    }

    if(!(state_)) {
        fprintf(stderr, "FAILED [thread_state]\n");
    } else {
        fprintf(stderr, "PASSED [thread_state]\n");
    }

    if(!(protect_)) {
        fprintf(stderr, "FAILED [change_page_protection]\n");
    } else {
        fprintf(stderr, "PASSED [change_page_protection]\n");
    }

    if(!(free_ & 1)) {
        fprintf(stderr, "FAILED [free memory] \n");
    } else {
        fprintf(stderr, "PASSED [free memory]\n");
    }

    fprintf(stderr, "PASSED [crash_callback]\n");

    task_terminate(info_struct->task);

    exit(-1);
}

int main(int argc, char* *argv) {
    mach_port_t task;
    x86_thread_state64_t *state;

//  infoPid = spawn_process("test");

    char *my_args[2];
    my_args[0] = "auto_test.app";
    my_args[1] = NULL;

    task = run("auto_test.app", my_args);

    long base_addr = get_base_address(task);

//   for(int i = 0; i < 10000000; i += 4096) {
//         change_page_protection(task, base_addr, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
//         base_addr += i;
//     }

    change_page_protection(task, base_addr, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);

    vm_region_basic_info_data_64_t *region_info= NULL;

    region_info = get_region_info(task, base_addr);
    printf("PROTECTIONS OF REGION ARE: %s\n", get_protection(region_info->protection));

    if(!strncmp(get_protection(region_info->protection), "rwx", 3)) {
        protect_ = 1;
    }

     void *x = allocate(task, 0,   4096, 1);

     if(x) {
        allocate_ = 1;
     }

     if(free_memory(task, (mach_vm_address_t)x, 4096)) {
        free_ = 1;
     }

     if((base_addr & 0xfff) == 0) {
        base_ = 1;
     }

     state = thread_state(task, 0);

     if(state) {
        state_ = 1;
     }
//    vm_region_t *vm_region_list[MAX_REGION];

//    get_region_info(task, base_addr, vm_region_list);

//    vm_region_basic_info_data_64_t *region_info= vm_region_list[0];

    //printf("PROTECTIONS OF REGION ARE: %s\n", get_protection(region_info->protection));

    mach_vm_address_t patch_addr = base_addr+0xd20;

    add_breakpoint(task, patch_addr, PERSISTENT, generic_callback);
    add_breakpoint(task, base_addr+0xe0e, ONE_TIME, generic_callback);
    add_breakpoint(task, base_addr+0xe3a, PERSISTENT, generic_callback);
// add_breakpoint(task, base_addr+0xd55, PERSISTENT, generic_callback);

    add_exception_callback(task, generic_callback_9, EXC_BAD_ACCESS);

    // tracking process creation
    add_exception_callback(task,generic_callback_3, NOTE_EXEC);
    add_exception_callback(task,generic_callback_2, NOTE_FORK);
    add_exception_callback(task,generic_callback_5, NOTE_SIGNAL);
    add_exception_callback(task,generic_callback_4, NOTE_EXIT);

//    start(task, infoPid);
    continue_(task);
    while(1);

    return 0;
}

