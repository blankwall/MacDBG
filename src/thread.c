#include "thread.h"

EXPORT
kern_return_t set_thread_state(mach_port_t thread, x86_thread_state64_t *break_state) {
    kern_return_t kret;

    kret = thread_set_state(thread, x86_THREAD_STATE64, (thread_state_t)break_state, x86_THREAD_STATE64_COUNT);
    EXIT_ON_MACH_ERROR("[-set_thread_state] failed", kret);

    return kret;
}

/*
    Given a thread populates a state and returns it
    states very much like a context
*/
EXPORT
x86_thread_state64_t* get_state(thread_act_port_t thread) {
    kern_return_t kret;
    x86_thread_state64_t *state;
    mach_msg_type_number_t stateCount = x86_THREAD_STATE64_COUNT;

    state = safe_malloc(sizeof(x86_thread_state64_t));
    kret = thread_get_state(thread, x86_THREAD_STATE64, (thread_state_t)state, &stateCount);
    RETURN_ON_MACH_ERROR("[-get_state] thread_get_state()", kret);

    return state;
}

//Get the state of thread 0 from a task
EXPORT
x86_thread_state64_t* thread_state(mach_port_t task, uint thread_count) {
    kern_return_t kret;
    thread_act_port_array_t threadList;
    mach_msg_type_number_t threadCount;
    x86_thread_state64_t *state;

    kret = task_threads(task, &threadList, &threadCount);
    RETURN_ON_MACH_ERROR("[-thread_stae] task_threads failed", kret);

    state = get_state(threadList[thread_count]);
    DEBUG_PRINT("STATE: %llx\n", state->__rip);

    return state;
}


EXPORT
kern_return_t thread_list_info(mach_port_t task,thread_act_port_array_t* threadList, mach_msg_type_number_t* threadCount) {
    kern_return_t kret;
    // thread_act_port_array_t* threadList = safe_malloc(sizeof(thread_act_port_array_t));
    // mach_msg_type_number_t threadCount;

    kret = task_threads(task, threadList, threadCount);
    RETURN_ON_MACH_ERROR("[-thread_list] task_threads failed", kret);

    return kret;
}

EXPORT
mach_msg_type_number_t thread_count(mach_port_t task) {
    kern_return_t kret;
    mach_msg_type_number_t threadCount;
    thread_act_port_array_t *threadList = safe_malloc(sizeof(thread_act_port_array_t));

    kret = task_threads(task, threadList, &threadCount);
    RETURN_ON_MACH_ERROR("[-thread_count] task_threads failed", kret);

    return threadCount;
}


/* NEED TO ADD HERE */


/* Get the basic information (thread_basic_info_t) about a given
   thread.
   Gives you the suspend count; thread state; user time; system time; sleep time; etc.
   The return value is a pointer to malloc'ed memory - it is the caller's
   responsibility to free it.  */

EXPORT
thread_basic_info_t get_thread_basic_info(thread_t thread) {
  kern_return_t kret;
  integer_t *thinfo = safe_malloc(sizeof(integer_t) * THREAD_INFO_MAX);
  mach_msg_type_number_t thread_info_count = THREAD_INFO_MAX;
  kret = thread_info (thread, THREAD_BASIC_INFO,(thread_info_t) thinfo, &thread_info_count);
  RETURN_ON_MACH_ERROR("[-get_thread_basic_info] failed", kret);

  return (thread_basic_info_t) thinfo;
}

/* Get the thread identifier info (thread_identifier_info_data_t)
   about a given thread.
   Gives you the system-wide unique thread number; the pthread identifier number
*/

EXPORT
thread_identifier_info_data_t* get_thread_identifier_info(thread_t thread) {
  kern_return_t kret;
  thread_identifier_info_data_t *tident = safe_malloc(sizeof(thread_identifier_info_data_t));
  mach_msg_type_number_t tident_count = THREAD_IDENTIFIER_INFO_COUNT;
  kret = thread_info (thread, THREAD_IDENTIFIER_INFO, (thread_info_t)tident, &tident_count);
  RETURN_ON_MACH_ERROR("[-get_thread_identifier_info] failed", kret);

  return tident;
}


EXPORT
kern_return_t thread_terminate_(mach_port_t thread) {
    thread_terminate(thread);

    return thread_terminate(thread);
}

EXPORT
kern_return_t thread_suspend_(mach_port_t thread) {
    return thread_suspend(thread);
}

EXPORT
kern_return_t thread_resume_(mach_port_t thread) {
    return thread_resume(thread);;
}

EXPORT
proc_threadinfo_t* get_proc_threadinfo (pid_t pid, uint64_t thread_handle) {
  struct proc_threadinfo *p_th;
  p_th = safe_malloc(sizeof(struct proc_threadinfo));
  p_th->pth_name[0] = '\0';
  int ret = proc_pidinfo (pid, PROC_PIDTHREADINFO, thread_handle, p_th, sizeof(struct proc_threadinfo));
  if (ret != 0)
    return p_th;
  else
    return NULL;
}
