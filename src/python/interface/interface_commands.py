from py_libs.macdbg import MacDbg
from py_libs.structs import ExcMsg, X86ThreadState64, BreakpointStruct, ExceptionHandler, VmRegionBasicInfo64, VmRegion
from py_libs.utils.enums import *

from py_libs.utils.util import *

from ctypes import *
import os, psutil, time

def generic_callback(info_struct):
    LOG("Breakpoint hit")
    print info_struct.contents
    return 1

def info(dbg, params):
    usage = "\tUsage: info proc"

    if len(params) == 0:
        print usage
        return

    if params[0] == "proc":
        base_addr = dbg.get_base_address()
        if base_addr:
            print "Process Base: {0}".format(base_addr)

def help(dbg, params):
    pass

def run(dbg, params):
    usage = "\tUsage: run [cmd] [args...]"

    if len(params) == 0:
        print usage
        return

    p = subprocess.Popen(params,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    return iter(p.stdout.readline, b'')

def quit(dbg, params):
    try:
        dbg.detach()
    except:
        pass
    print "Bye"
    exit(0)

def do_print(dbg, params):
    usage = "\tUsage: print [args...]"

    if len(params) == 0:
        print usage
        return

    return eval(" ".join(params))

def process_list(dbg, params):
    def print_processes(process=""):
        for proc in psutil.process_iter():
            try:
                pinfo = proc.as_dict(attrs=['pid', 'name'])
            except psutil.NoSuchProcess:
                pass
            else:
                if process in pinfo["name"]:
                    print "[{0}]: {1}".format(pinfo["pid"], pinfo["name"])

    if len(params) == 1:
        print_processes(params[0])
    else:
        print_processes()

def attach(dbg, params):
    usage = "\tUsage: attach [pid]"

    if len(params) == 0:
        print usage
        return

    try:
        pid = int(params[0])
    except ValueError:
        ERR("Given pid is not valid: {0}".format(pid))

    dbg.attach(pid)

    CALLBKFUNC = CFUNCTYPE(c_int, POINTER(ExcMsg))
    gen_callback = CALLBKFUNC(generic_callback)

    dbg.add_exception_callback(gen_callback, EXC_BAD_ACCESS)
    dbg.add_exception_callback(gen_callback, NOTE_EXEC)
    dbg.add_exception_callback(gen_callback, NOTE_FORK)
    dbg.add_exception_callback(gen_callback, NOTE_SIGNAL)
    dbg.add_exception_callback(gen_callback, NOTE_EXIT)

def detach(dbg, params):
    dbg.detach()

def kill(dbg, params):
    os.kill(dbg.pid, signal.SIGKILL)

def set_break(dbg, params):
    usage = "\tUsage: break [addr]"

    if len(params) == 0:
        print usage
        return

    CALLBKFUNC = CFUNCTYPE(c_int, POINTER(ExcMsg))
    gen_callback = CALLBKFUNC(generic_callback)

    try:
        addr = int(params[0], 0)
    except ValueError:
        ERR("Given address is not valid: {0}".format(params[0]))
        return

    CALLBKFUNC = CFUNCTYPE(c_int, POINTER(ExcMsg))
    gen_callback = CALLBKFUNC(generic_callback)

    base_addr = dbg.get_base_address()
    dbg.add_breakpoint(base_addr+0xe0e, PERSISTENT, gen_callback)
    dbg.add_breakpoint(base_addr+0xe3a, PERSISTENT, gen_callback)
    dbg.list_breaks();

    gen_callback_2 = CALLBKFUNC(generic_callback)
    gen_callback_3 = CALLBKFUNC(generic_callback)
    gen_callback_4 = CALLBKFUNC(generic_callback)
    gen_callback_5 = CALLBKFUNC(generic_callback)
    gen_callback_9 = CALLBKFUNC(generic_callback)

    dbg.add_exception_callback(gen_callback_9, EXC_BAD_ACCESS)

    # tracking process creation
    dbg.add_exception_callback(gen_callback_3, NOTE_EXEC)
    dbg.add_exception_callback(gen_callback_2, NOTE_FORK)
    dbg.add_exception_callback(gen_callback_5, NOTE_SIGNAL)
    dbg.add_exception_callback(gen_callback_4, NOTE_EXIT)

    #start(task, infoPid);
    dbg.continue_()
    #while(1);
    time.sleep(10)

def set_temp_break(dbg, params):
    usage = "\tUsage: tbreak [addr]"

    if len(params) == 0:
        print usage
        return

    CALLBKFUNC = CFUNCTYPE(c_int, POINTER(ExcMsg))
    gen_callback = CALLBKFUNC(generic_callback)

    try:
        addr = int(params[0], 0)
    except ValueError:
        ERR("Given address is not valid: {0}".format(params[0]))
        return

    dbg.add_breakpoint(addr, ONE_TIME, gen_callback)

def examine(dbg, params):
    usage = "\tUsage: examine [size] [type] [addr]"

    if len(params) == 0:
        print usage
        return

def disassemble(dbg, params):
    pass

def clear(dbg, params):
    pass

def delete(dbg, params):
    pass

def do_continue(dbg, params):
    LOG("Continuing...")
    dbg.continue_()
    return True

def step(dbg, params):
    pass

def next(dbg, params):
    pass

def read_regs(dbg, params):
    pass

def write_regs(dbg, params):
    pass

def read_memory(dbg, params):
    pass

def write_memory(dbg, params):
    pass

def backtrace(dbg, params):
    pass
