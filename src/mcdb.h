#ifndef U_H
#define U_H

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
#include <err.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>
#include "./.mach_gen/mach_exc.h"
#include "dyldcache_parser.h"

#define EXPORT __attribute__((visibility("default")))

#define MAX_BREAKS 100

#define DEBUG_PRINT(fmt, ...) \
            do { if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

#define EXIT_ON_MACH_ERROR(msg, retval) \
        if (kret != KERN_SUCCESS) {mach_error(msg ":" , kret); exit((retval)); }

#define RETURN_ON_MACH_ERROR(msg, retval) \
        if (kret != KERN_SUCCESS) {\
            return 0;\
        }

#define UNREFERENCED_PARAMETER(x) x

#define MAX_EXCEPTION 100

#ifndef DEBUG
#define DEBUG 0
#endif

enum state {SUSPEND, CONTINUE};

typedef struct exc_msg {
    mach_port_t exception_port;
    mach_port_t thread;
    mach_port_t task;
    exception_type_t exception;
    mach_exception_data_t code;
    mach_msg_type_number_t codeCnt;
}exc_msg_t;

typedef int (*callback)(exc_msg_t *info_struct);

// change
typedef struct {
    vm_offset_t original;
    vm_address_t address;
    callback handler;
    int flags;
    vm_address_t index;       // same type as address for remove_breakpoint
    unsigned int hit;
}breakpoint_struct;

// breakpoint_struct *breaks[MAX_BREAKS];
// unsigned int current_break;
// unsigned int single_step_index;   // HACK FOR NOW FIX ME LATER
// breakpoint_struct *single_step;


#include "breakpoint.h"


typedef struct exception_handler_type {
    exception_type_t exception;
    callback handler;
    mach_port_t task;
}exception_handler;


// exception_handler* except_list[MAX_EXCEPTION];
// int current_exception;

#include "exception.h"
#include "memory.h"

typedef struct interface {
    mach_port_t task;
    pid_t pid;
    
    breakpoint_struct** breaks;
    unsigned int current_break;
    unsigned int max_break;

    unsigned int single_step_index;   // HACK FOR NOW FIX ME LATER
    breakpoint_struct *single_step;

    exception_handler** except_list;
    unsigned int current_exception;
    unsigned int max_exception;


    int registered_exception_handler;
    int kq;
    mach_port_t server_port;
}interface;

typedef struct {
    interface **y;
    unsigned int x;
    unsigned int max_attach;
}point_list;

point_list bad_list;


#include "debug_main.h"

void* safe_malloc(size_t x);
void* safe_realloc(void *ptr, size_t x);
void print_byte(char *byte);
char* exception_to_string(exception_type_t exc);
void print_bytes(char *byte, int len);

#define MAX_EXCEPTION_PORTS 32

typedef struct {
  exception_mask_t masks[MAX_EXCEPTION_PORTS];
  exception_handler_t ports[MAX_EXCEPTION_PORTS];
  exception_behavior_t behaviors[MAX_EXCEPTION_PORTS];
  thread_state_flavor_t flavors[MAX_EXCEPTION_PORTS];
  mach_msg_type_number_t count;
}MachExceptionHandlerData;

// int kq;

// mach_port_t server_port;

#endif
