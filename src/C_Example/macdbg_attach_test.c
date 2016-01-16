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
Showing how to attach to multiple processes at once
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
    mach_port_t task;
    pid_t infoPid;
    //kern_return_t kret;
    //thread_act_port_array_t threadList;
    //mach_msg_type_number_t threadCount;
    x86_thread_state64_t *state;
    int task_[9];


    int pid[] = {
                24556,
                24581,
                24606,
                24631,
                24656,
                24681,
                24706,
                24731,
                24756};

    int count = 0;

    while(count < 9){
        task = attach(pid[count]);
        printf("ATTACHED TO PROCESS %d WITH TASK %d\n", pid[count], task);
        task_[count] = task;
        count += 1;
    }

    mach_vm_address_t k;
    mach_vm_address_t patch_addr;

    count= 0;
    while(count < 9){
        task = task_[count];
        k = get_base_address(task) + 0xf1e;
        printf("READ MEMORY TEST: %s\n", (char*)read_memory(task, k, 4));
        patch_addr = get_base_address(task)+0xd90;
        add_breakpoint(task, patch_addr, ONE_TIME, generic_callback);
        count += 1;
    }

    while(1);
    return 0;
}

