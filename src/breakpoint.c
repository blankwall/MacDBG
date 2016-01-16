#include "breakpoint.h"
#include "memory.h"

/*
 * Add a breakpoint, anything <= MAX_BREAKS is reserved as an index.
 * We justify this as we plan on MAX_BREAKS to be between 100 to 10,000.
 */
EXPORT
int add_breakpoint(mach_port_t task, vm_address_t patch_addr, int cont, callback handler) {
    kern_return_t kret;
    char *tmp;
    mach_vm_size_t len = 1;     // number of bytes to write
    uint8_t opcode = 0xcc;      // the CC byte to write
    interface *face;

    face = find_interface(task);
    if(face->registered_exception_handler == 0) {
        DEBUG_PRINT("[+add_breakpoint] HERE IN ADD BREAK\n %d", 0);
        register_(task);
    }

    kret = mach_vm_protect(task, patch_addr, len, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    RETURN_ON_MACH_ERROR("[-add_breakpoint] mach_vm_protect()", kret);

    if (patch_addr <= MAX_BREAKS) {
        DEBUG_PRINT("[-add_breakpoint] INVALID BREAKPOINT ADDRESS %lx\n", patch_addr);
        return -1;
    } else if(face->current_break >= MAX_BREAKS) {
        DEBUG_PRINT("[-add_breakpoint] Max %d breaks reached!\n", MAX_BREAKS);
        return -1;
    }

    DEBUG_PRINT("[+add_breakpoint] Breakpoint %u: %lx added\n", face->current_break, patch_addr);
    tmp = (char*) read_memory(task, patch_addr, 1);

    breakpoint_struct *new_break = safe_malloc(sizeof(breakpoint_struct));
    new_break->address = patch_addr;
    new_break->original = tmp[0] & 0xff;
    new_break->handler = handler;
    if(face->single_step) {
        new_break->index = face->single_step_index;
    }
    else {
        new_break->index = face->current_break == 0 ? 0 : face->breaks[face->current_break-1]->index + 1;
    }
    new_break->flags = cont;


    if(face->max_break == 0) {
        face->max_break = 1;
    }

    if(face->current_break >= (face->max_break - 1)) {
        DEBUG_PRINT("[+add_breakpoint] ALLOCATING MORE BP! CURRENTLY: %d\n", face->current_break);
        face->breaks = safe_realloc(face->breaks, sizeof(breakpoint_struct*)  *(face->max_break*2));
        face->max_break *= 2;
    }

    // face->breaks = safe_realloc(face->breaks, sizeof(breakpoint_struct*)  *(face->current_break+1));
    face->breaks[face->current_break++] = new_break;

    write_memory(task, patch_addr, opcode, len); // write the byte
    kret = mach_vm_protect(task, patch_addr, (mach_vm_size_t)1, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    RETURN_ON_MACH_ERROR("[-add_breakpoint] RESTORE mach_vm_protect()", kret);

    return 1;
}

/*
 * Removes a breakpoint from breaks array indicated by index or address (both are unsigned long long)
 */
EXPORT
int remove_breakpoint(mach_port_t task, vm_address_t bp) {
    kern_return_t kret;
    int c, position, index;
    mach_vm_address_t address;
    interface *face;

    face = find_interface(task);
    if(!face->registered_exception_handler) {
        DEBUG_PRINT("SHOULD NEVER HAPPEN :| %d\n", 1);
        return -1;
    }

    position = find_break(task, bp);
    if(position == -1) {
        DEBUG_PRINT("[-remove_breakpoint] Failed find_break %d\n", position);
        return -1;
    }

    breakpoint_struct *breakpoint = face->breaks[position];

    uint8_t opcode = breakpoint->original;                  // CC byte to write
    mach_vm_size_t len = 1;                                 // number of bytes to write

    kret = mach_vm_protect(task, breakpoint->address, len, FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    RETURN_ON_MACH_ERROR("[-remove_breakpoint] mach_vm_protect()", kret);

    write_memory(task, breakpoint->address, opcode, len);   // and write the byte

    kret = mach_vm_protect(task, breakpoint->address, len, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    RETURN_ON_MACH_ERROR("[-remove_breakpoint] RESTORE mach_vm_protect()", kret);

    address = face->breaks[position]->address;
    index = face->breaks[position]->index;

    if(face->single_step) face->single_step_index = index;

    for(c = position; c < face->current_break; c++) {
        face->breaks[c] = face->breaks[c+1];
    }

    DEBUG_PRINT("[-remove_breakpoint] Breakpoint %x at %llx removed\n", index, address);
    face->current_break -= 1; // decrement counter

    return 1;
}

EXPORT
int remove_all_breaks(mach_port_t task) {
    interface *face = find_interface(task);

    int i = face->current_break-1;
    while(i>=0) {
        remove_breakpoint(task, face->breaks[i]->address);
        --i;
    }

    return 1;
}

EXPORT
vm_address_t* list_breaks(mach_port_t task, int *count) {
    interface *face = find_interface(task);
    vm_address_t *list  = safe_malloc(sizeof(vm_address_t) * face->current_break);
    int i = 0;

    while(i < face->current_break) {
        DEBUG_PRINT("[+list_breaks] Breakpoint [%lu] %lx\n", face->breaks[i]->index, face->breaks[i]->address);
        list[i] = face->breaks[i]->address;
        ++i;
    }
    *count = i;
    return list;
}


int find_break(mach_port_t task, vm_address_t find) {
    interface *face = find_interface(task);
    int i = 0;
    //DEBUG_PRINT("[+find_break] Searching FOR -- %lx\n", address);

    while(i < face->current_break) {
        //DEBUG_PRINT(("%d\n", i));
        if(face->breaks[i]) {
            if(face->breaks[i]->address == find)
                return i;
            else if(face->breaks[i]->index == find)
                return i;
        } else {
            DEBUG_PRINT("[-find_break] INVALID Address or Index %d", i);
            getchar();
        }
        i++;
    }

    return -1;
}
