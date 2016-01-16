#ifndef E_H
#define E_H
#include "mcdb.h"

int add_exception_callback(mach_port_t task, callback handler, exception_type_t exception);
int remove_exception_callback(exception_handler *exc);
int remove_all_exception_callbacks(mach_port_t task);

#endif
