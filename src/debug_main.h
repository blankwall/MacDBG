#ifndef D_H
#define D_H
#include "mcdb.h"
#include "thread.h"

extern boolean_t mach_exc_server (mach_msg_header_t *msg, mach_msg_header_t *reply);
int handle_break(exc_msg_t *exc);
mach_port_t get_task(pid_t infoPid);
int start(mach_port_t task, pid_t infoPid);
int generic_callback(exc_msg_t *info_struct);
int generic_callback_2(exc_msg_t *info_struct);
mach_port_t attach(pid_t infoPid);
mach_port_t detach(mach_port_t task);
int stop(mach_port_t task);
int terminate_(mach_port_t task);
void test();
void* kqueue_loop(int kp);
int persistent_break(exc_msg_t *exc);
mach_port_t suspend(mach_port_t task);
mach_port_t continue_(mach_port_t task);
pid_t spawn_process(char *command, char *args[]);
mach_port_t run(char *command, char *args[]);
interface* find_interface(mach_port_t task);
void register_(mach_port_t thread);

#endif
