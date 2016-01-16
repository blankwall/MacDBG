#include "debug_main.h"

interface *find_interface(mach_port_t task) {
    int count = 0;

    while(count < bad_list.x) {
        if(bad_list.y[count]->task == task) {
            return bad_list.y[count];
        }
        count++;
    }
    return NULL;
}

EXPORT
int generic_callback(exc_msg_t *info_struct) {
    printf("\n[+generic_callback] BREAKPOINT CALLBACK %p\n", info_struct->code);
    return 1;
}

int handle_break(exc_msg_t *exc) {
    interface* face;
    int ret, our_break;
    kern_return_t kret;
    x86_thread_state64_t *break_state;

    break_state = get_state(exc->thread);
    our_break = find_break(exc->task, break_state->__rip-1);

    //find_break returns -1 aka big unsigned int
    if(our_break == -1) {
        return -1;
    }

    face = find_interface(exc->task);
    face->breaks[our_break]->hit++;
    breakpoint_struct *actual = face->breaks[our_break];

    if(actual->flags == ONE_TIME) {
        remove_breakpoint(exc->task, actual->address);  //restore original byte
        break_state->__rip = actual->address;           //Restore original rip -- 1 byte back
    } else if(actual->flags == PERSISTENT) {
        face->single_step = actual;
        break_state->__rflags |= 0x100;                 //TRAP FLAG
        remove_breakpoint(exc->task, actual->address);
        break_state->__rip = actual->address;
    }

    kret = thread_set_state(exc->thread, x86_THREAD_STATE64, (thread_state_t)break_state, x86_THREAD_STATE64_COUNT);
    RETURN_ON_MACH_ERROR("[-handle_break] failed setting thread state", kret);

    if(actual->handler) {
        ret = actual->handler(exc);
        if(ret == -1) {
            return -1;
        }
    }

    return 1;
}

EXPORT
int find_pid(mach_port_t task) {
    interface *face = find_interface(task);
    return face->pid;
}

int persistent_break(exc_msg_t *exc) {
    interface *face;
    x86_thread_state64_t *break_state;
    kern_return_t kret;

    break_state = get_state(exc->thread);
    face = find_interface(exc->task);
    DEBUG_PRINT("[+presistent_break] single_step %lx\n", face->single_step->address);

    add_breakpoint(exc->task, face->single_step->address, PERSISTENT, face->single_step->handler);

    free(face->single_step);
    face->single_step = NULL;
    break_state->__rflags &= ~0x100;

    kret = thread_set_state(exc->thread, x86_THREAD_STATE64, (thread_state_t)break_state, x86_THREAD_STATE64_COUNT);
    RETURN_ON_MACH_ERROR("[-persistent_break] failed setting thread state", kret);

    return 1;
}

// Handle EXCEPTION_DEFAULT behavior
kern_return_t catch_mach_exception_raise(mach_port_t exception_port,
                                         mach_port_t thread,
                                         mach_port_t task,
                                         exception_type_t exception,
                                         mach_exception_data_t code,
                                         mach_msg_type_number_t codeCnt) {

    int ret, list;
    char *except;
    exc_msg_t *exc;
    interface *face;

    task_suspend(thread);

    // Populate structure to give to callback
    exc = safe_malloc(sizeof(exc_msg_t));
    exc->exception_port = exception_port;
    exc->thread = thread;
    exc->task = task;
    exc->exception = exception;
    exc->code = code;
    exc->codeCnt = codeCnt;

    // -1  == failure to handle pass fail to kernel
    // 0 == continue on 
    // 1 == all done 

    ret = -1;
    face = find_interface(task);
    //REGISTER EXCEPTION HANDLER LOOP THROUGH EXCEPTION LIST CALLING EXCEPTION HANDLED FUNCITONS FIRST
    for(list = 0; list < face->current_exception; list++) {
        if(face->except_list[list]->exception == exception) {
            ret = face->except_list[list]->handler(exc);
            if(ret == -1) {
                return KERN_FAILURE;
            } else if(ret == 1){
                return KERN_SUCCESS;
            }
        }
    }

    switch(exception) {
        case EXC_BREAKPOINT: //DEFAULT BREAKPOINT HANDLE HANDLED AFTER EXCEPTIONS ARE HANDLED
                if(face->single_step == NULL) {
                    ret = handle_break(exc);
                    if(ret == -1) {
                        DEBUG_PRINT("[-catch_mach_exception_raise] HANDLE BREAK FAILURE %d\n", -1);
                        return KERN_FAILURE;
                    }
                } else {
                    persistent_break(exc);
                    break;
                }
                break;
        case EXC_SOFTWARE       : /* Software generated exception */ //INT3
        case EXC_BAD_ACCESS     : /* Could not access memory */
        case EXC_BAD_INSTRUCTION: /* Instruction failed */
        case EXC_ARITHMETIC     : /* Arithmetic exception */
        case EXC_EMULATION      : /* Emulation instruction */
        case EXC_SYSCALL        : /* System calls. */
        case EXC_MACH_SYSCALL   : /* Mach system calls. */
        case EXC_RPC_ALERT      : /* RPC alert */
        case EXC_CRASH          : /* Abnormal process exit */
        case EXC_RESOURCE       : /* Hit resource consumption limit */
        case EXC_GUARD          : /* Violated guarded resource protections */
        default:
            if (ret == 0){
                break;
            }
            except = exception_to_string(exception);
            DEBUG_PRINT("[-catch_exception_raise] UNHANDLED EXCEPTION %s\n", except);
            thread_terminate(thread);
            break;
    }

    task_resume(thread);
    free(exc);

    return KERN_SUCCESS;
}

// Handle EXCEPTION_DEFAULT behavior
kern_return_t catch_mach_exception_raise_state(mach_port_t exception_port,
                                               mach_port_t thread,
                                               mach_port_t task,
                                               exception_type_t exception,
                                               mach_exception_data_t code,
                                               mach_msg_type_number_t codeCnt) {
    return KERN_FAILURE;
}

// Handle EXCEPTION_DEFAULT behavior
kern_return_t catch_mach_exception_raise_state_identity(mach_port_t exception_port,
                                                        mach_port_t thread,
                                                        mach_port_t task,
                                                        exception_type_t exception,
                                                        mach_exception_data_t code,
                                                        mach_msg_type_number_t codeCnt) {
    return KERN_FAILURE;
}

static void* exception_server (mach_port_t exceptionPort) {
    mach_msg_return_t rt;
    mach_msg_header_t *msg;
    mach_msg_header_t *reply;

    msg   = safe_malloc(sizeof(union __RequestUnion__mach_exc_subsystem));
    reply = safe_malloc(sizeof(union __ReplyUnion__mach_exc_subsystem));

    while (1) {
         rt = mach_msg(msg, MACH_RCV_MSG, 0, sizeof(union __RequestUnion__mach_exc_subsystem), exceptionPort, 0, MACH_PORT_NULL);

         if (rt!= MACH_MSG_SUCCESS) {
            DEBUG_PRINT("[-exception_server] MACH_RCV_MSG stopped, exit from exception_server thread :%d\n", 1);
            return "MACH_RCV_MSG_FAILURE";
         }
         /*
          * Call out to the mach_exc_server generated by mig and mach_exc.defs.
          * This will in turn invoke one of:
          * mach_catch_exception_raise()
          * mach_catch_exception_raise_state()
          * mach_catch_exception_raise_state_identity()
          * .. depending on the behavior specified when registering the Mach exception port.
          */
         mach_exc_server(msg, reply);

         // Send the now-initialized reply
         rt = mach_msg(reply, MACH_SEND_MSG, reply->msgh_size, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);

         if (rt!= MACH_MSG_SUCCESS) {
            return "MACH_SEND_MSG_FAILURE";
         }
    }
}

EXPORT
void* kqueue_loop(int kp) {
    struct kevent ke;      /* event that was triggered */
    int i, list, ret, handled;
    mach_port_t task;
    exc_msg_t *exc;

    int infoPid = kp;
    task_for_pid(current_task(), infoPid, &task);
    interface* face = find_interface(task);


    DEBUG_PRINT("[+kqueue_loop] KQUEUE PID of prog: %d\n", infoPid);
    face->kq = kqueue();         /* create a new kernel event queue */
    if (face->kq == -1) {
        fprintf(stderr, "[-kqueue_loop] %d\n", face->kq);
    }

    /* initalize kevent structure */
    EV_SET(&ke, infoPid, EVFILT_PROC, EV_ADD | EV_ENABLE, NOTE_SIGNAL | NOTE_FORK | NOTE_EXIT | NOTE_EXEC  , 0, 0);

    i = kevent(face->kq, &ke, 1, NULL, 0, NULL); //adding event

    if (face->kq == -1) {
        fprintf(stderr, "[-kqueue_loop] %d\n", face->kq);
    }

    for(;;) {
        i = kevent(face->kq, NULL, 0, &ke, 1, NULL); //checking for change kevent
        if (i==-1) {
            DEBUG_PRINT("[+kqueue_loop] kevent stopped, exit from kqueue_loop thread: %d\n", 1);
            return "KEVENT_STOPPED";
        }

        task_suspend(task);

        exc = malloc(sizeof(exc_msg_t));
        exc->task = task;
        exc->exception = ke.fflags;

        //REGISTER EXCEPTION HANDLER LOOP THROUGH EXCEPTION LIST CALLING EXCEPTION HANDLED FUNCITONS FIRST
        for(list = 0; list < face->current_exception; list++) {
            if(face->except_list[list]->exception & ke.fflags) {
                handled = 1;
                ret = face->except_list[list]->handler(exc);
                if(ret == -1) {
                    fprintf(stderr, "[-kqueue_loop] UNABLE TO HANDLE EVENT: %d\n", ke.fflags);
                    exit(-1);
                }
            }
        }
        if(handled == 0) {
            DEBUG_PRINT("[-kqueue_loop] FAILED TO HANDLE :/ %d\n", 0);
            task_resume(task);
            continue;
        }

        handled = 0;
        task_resume(task);
    }
}

mach_port_t get_task(pid_t infoPid) {
    kern_return_t kret;
    mach_port_t task;

    DEBUG_PRINT("[+getstate] Trying pid %d\n", infoPid);

    kret = task_for_pid(current_task(), infoPid, &task);
    RETURN_ON_MACH_ERROR("[-get_state] task_for_pid failed", kret);

    return task;
}

EXPORT
int terminate_(mach_port_t task) {
    kern_return_t kret;
    pid_t pid;

    pid_for_task(task, &pid);
    kret = kill(pid, PT_KILL);
    mach_error("[-terminate] kill process status:" , kret);

    return 1;
}

EXPORT
void test() {
    printf("[+test] KERN_SUCCESS\n");
}

EXPORT
mach_port_t attach(pid_t infoPid) {
    mach_port_t task;
    int count = 0;

    task = get_task(infoPid);
    if(task == 0) {
        int kret = 0;
        RETURN_ON_MACH_ERROR("[-attach] invalid pid", kret);
    }

    if(bad_list.max_attach == 0) {
        bad_list.max_attach = 1;
    }

    while(count < bad_list.x) {
        if(bad_list.y[count]->task == task) {
            int kret = 0;
            RETURN_ON_MACH_ERROR("[-attach] duplicate pid", kret);
        }
        count++;
    }

    if(bad_list.x >= (bad_list.max_attach - 1)) {
        DEBUG_PRINT("ALLOCATING MORE! CURRENTLY: %d\n", bad_list.max_attach);
        bad_list.y = realloc(bad_list.y, sizeof(interface*) * (bad_list.max_attach*2));
        bad_list.max_attach *= 2;
    }


    bad_list.y[bad_list.x] = malloc(sizeof(interface*));

    interface* tmp = malloc(sizeof(interface));
    memset(tmp, 0, sizeof(interface));

    tmp->task = task;
    tmp->pid = infoPid;
    tmp->current_break = 0;
    tmp->current_exception = 0;
    tmp->single_step = NULL;
    tmp->registered_exception_handler = 0;

    bad_list.y[bad_list.x++] = tmp;

    DEBUG_PRINT("ATTACHING TO PROCESS # %d\n", bad_list.x);
    return task;
}

void register_(mach_port_t task) {
    interface* face = find_interface(task);
    start(task, face->pid);
    face->registered_exception_handler = 1;
}

EXPORT
mach_port_t suspend(mach_port_t task) {
    printf("SUSPENDING TASK!\n");
    task_suspend(task);

    return task;
}

EXPORT
mach_port_t continue_(mach_port_t task) {
    task_resume(task);

    return task;
}

EXPORT
mach_port_t detach(mach_port_t task) {
    int ret=0;

    ret = remove_all_breaks(task);

    if (!ret) {
        DEBUG_PRINT("[-detach] Failed to remove all breaks %d\n", ret);
    }
    DEBUG_PRINT("[+detach] Removed all breaks %d\n", ret);
    ret = remove_all_exception_callbacks(task);

    if (!ret) {
        DEBUG_PRINT("[-detach] Failed to remove all exception callbacks %d\n", ret);
    }
    DEBUG_PRINT("[+detach] Removed all exception callbacks %d\n", ret);
    ret = stop(task);   //stop debugger threads

    if (!ret) {
        DEBUG_PRINT("[-detach] Failed to detach debugger threads %d\n", ret);
    }
    DEBUG_PRINT("[+detach] Done detaching Debugger threads %d\n", ret);

    return 1;
}

EXPORT
pid_t spawn_process(char *command, char *args[]) {
    pid_t pid = fork();

    switch (pid) {
    case -1: // error
        perror("fork");
        exit(1);
    case 0:             // child process
        execv(command, args);   // run the command
        perror("[-spawn_process] execl");   // execl doesn't return unless there is a problem
        exit(1);
    default:

        return pid;
    }

}

EXPORT
mach_port_t run(char *command, char *args[]) {
    pid_t infoPid;

    infoPid = spawn_process(command, args);
    usleep(1 * 1000);
    return attach(infoPid);
}

EXPORT
int start(mach_port_t task, pid_t infoPid) {
    kern_return_t kret;
    pthread_t tid[2];
    interface* face = find_interface(task);

    kret = mach_port_allocate(current_task(), MACH_PORT_RIGHT_RECEIVE, &face->server_port);
    RETURN_ON_MACH_ERROR("[-start] mach_port_allocate failed", kret);

    kret = mach_port_insert_right(current_task(), face->server_port, face->server_port, MACH_MSG_TYPE_MAKE_SEND);
    RETURN_ON_MACH_ERROR("[-start] mach_port_insert_right failed", kret);

    kret = task_set_exception_ports(task, EXC_MASK_ALL, face->server_port, EXCEPTION_DEFAULT|MACH_EXCEPTION_CODES, THREAD_STATE_NONE);
    RETURN_ON_MACH_ERROR("[-start] task_set_exception_ports failed", kret);

    int err = pthread_create(&tid[0], NULL, (void *(*)(void*))kqueue_loop, (void *)(unsigned long long)infoPid);
    if (err != 0)
        DEBUG_PRINT("\n[-start] can't create thread :[%s]", strerror(err));
    else
        DEBUG_PRINT("\n[-start] Thread created successfully %d\n", 0);

    err = pthread_create(&tid[1], NULL, (void *(*)(void*))exception_server, (void *(*)(void*))(unsigned long long)face->server_port);
    if (err != 0)
        DEBUG_PRINT("\n[-start] can't create thread :[%s]", strerror(err));
    else
        DEBUG_PRINT("\n[-start] Thread created successfully %d\n", 0);

    return 1;
}

//No synchronization issue so far, need to use synchronize if we run into any issues
int stop(mach_port_t task) {
    MachExceptionHandlerData old_handler;
    thread_act_port_array_t threadList;
    mach_msg_type_number_t threadCount;
    unsigned int count;
    kern_return_t kret;
    interface *face;

    threadCount=0;
    task_threads(current_task(), &threadList, &threadCount);
    DEBUG_PRINT("[+stop] Thread count before detaching %d\n", threadCount);

    face = find_interface(task);
    close(face->kq);                  //close kqueue
    count = 1;
    kret = task_swap_exception_ports(current_task(),
                                     EXC_MASK_ALL,
                                     MACH_PORT_NULL,
                                     EXCEPTION_DEFAULT|MACH_EXCEPTION_CODES,
                                     THREAD_STATE_NONE,
                                     (exception_mask_array_t) old_handler.masks,
                                     (mach_msg_type_number_t *) &old_handler.count,
                                     (exception_handler_array_t) old_handler.ports,
                                     (exception_behavior_array_t) old_handler.behaviors,
                                     (exception_flavor_array_t) old_handler.flavors);

    kret = mach_port_mod_refs(mach_task_self(), face->server_port, MACH_PORT_RIGHT_RECEIVE, -1);

    if (kret != KERN_SUCCESS) {
        RETURN_ON_MACH_ERROR("[-stop] mach_port_mod_refs failed", kret);
    }

    kret = mach_port_get_refs(mach_task_self(), face->server_port, MACH_PORT_RIGHT_RECEIVE, &count );
    RETURN_ON_MACH_ERROR("[-stop] mach_port_get_refs failed", kret);


    if (face->server_port) {
        kret = mach_port_deallocate(current_task(),face->server_port);
        RETURN_ON_MACH_ERROR("[-stop] mach_port_deallocate failed", kret);
    }

    if (count) {
        DEBUG_PRINT("[-stop] failed to reset server port ref count exp:0 actual: %d\n", count);
        return 0;
    }

    task_threads(task, &threadList, &threadCount);
    DEBUG_PRINT("[+stop] Thread count after detaching %d\n", threadCount);

    face->registered_exception_handler = 0;
    count = 0;

    //REMOVE PID FROM BAD LIST TO ALLOW REATTACHING
    while(count < bad_list.x) {
        if(bad_list.y[count]->task == task) {
            break;
        }
        count++;
    }

    DEBUG_PRINT("TASK IS NUMBER: %d\n", count);

    int c;
    for(c = count; c < bad_list.x; c++) {
        bad_list.y[c] =  bad_list.y[c+1];
    }
    bad_list.x -= 1;

    return 1;
}

