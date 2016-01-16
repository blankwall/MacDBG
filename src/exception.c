#include "exception.h"

EXPORT
int add_exception_callback(mach_port_t task, callback handler, exception_type_t exception) {
    interface *face;
    exception_handler *my_exc;

    face = find_interface(task);
    if(!face->registered_exception_handler) {
        register_(task);
    }

    if(face->current_exception > MAX_EXCEPTION) {
        DEBUG_PRINT("[-add_exception_callback] TOO MANY EXCEPTION HANDLERS -- %d\n", face->current_exception);
        return -1;
    }

    my_exc = safe_malloc(sizeof(exception_handler));
    my_exc->exception = exception;
    my_exc->handler = handler;
    my_exc->task = task;

    if(face->max_exception == 0) {
        face->max_exception = 1;
    }

    if(face->current_exception >= (face->max_exception - 1)) {
        DEBUG_PRINT("ALLOCATING MORE EXC! CURRENTLY: %d\n", face->current_exception);
        face->except_list = safe_realloc(face->except_list, sizeof(exception_handler*) * (face->max_exception*2));
        face->max_exception *= 2;
    }

    face->except_list[face->current_exception] = my_exc;
    face->current_exception += 1;

    return 1;
}

EXPORT
int remove_exception_callback(exception_handler *exc) {
    interface *face;
    int c, position;
    
    face = find_interface(exc->task);
    position = -1;
    for(c = 0; c < face->current_exception; c++) {
        if(face->except_list[c] == exc) {
            position = c;
            break;
        }
    }

    if(position == -1) {
        DEBUG_PRINT("[-remove_exception_callback] ERROR finding exception callback %d", 1 );
        return -1;
    }

    for(c = position; c < face->current_exception; c++) {
        face->except_list[c] = face->except_list[c+1];
    }
    face->current_exception -= 1;
    DEBUG_PRINT("[+remove_exception_callback] EXCEPTION REMOVED %d\n", 1);

    return 1;
}

EXPORT
int remove_all_exception_callbacks(mach_port_t task) {
    interface *face = find_interface(task);
    int i = 0;
    while(i < face->current_exception) {
        DEBUG_PRINT("[+remove_all_exception_callbacks] exception callback: %s removed\n",
                    exception_to_string(face->except_list[i]->exception));
        face->except_list[i]=NULL;
        ++i;
    }
    face->current_exception = 0;

    return 1;
}

