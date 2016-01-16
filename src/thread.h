#ifndef T_H
#define T_H
#include "mcdb.h"

typedef struct proc_threadinfo proc_threadinfo_t;

x86_thread_state64_t* get_state(thread_act_port_t thread);
kern_return_t set_thread_state(mach_port_t thread, x86_thread_state64_t *break_state);
x86_thread_state64_t* thread_state(mach_port_t task, uint count);
kern_return_t thread_list_info(mach_port_t task,thread_act_port_array_t* threadList, mach_msg_type_number_t* threadCount);
kern_return_t thread_terminate_(mach_port_t thread);
kern_return_t thread_suspend_(mach_port_t thread);
kern_return_t thread_resume_(mach_port_t thread);
thread_identifier_info_data_t* get_thread_identifier_info(thread_t thread);
thread_basic_info_t get_thread_basic_info (thread_t thread);
proc_threadinfo_t* get_proc_threadinfo (pid_t pid, uint64_t thread_handle);
mach_msg_type_number_t thread_count(mach_port_t task);

#endif
