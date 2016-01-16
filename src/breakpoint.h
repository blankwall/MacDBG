#ifndef B_H
#define B_H

#include "mcdb.h"

#define ONE_TIME  0
#define PERSISTENT 1


int add_breakpoint(mach_port_t task, vm_address_t patch_addr, int cont, callback handler);
int remove_breakpoint(mach_port_t task, vm_address_t address);
int remove_all_breaks(mach_port_t task);
int find_break(mach_port_t task, vm_address_t address);
vm_address_t* list_breaks(mach_port_t task, int* count);

#endif
