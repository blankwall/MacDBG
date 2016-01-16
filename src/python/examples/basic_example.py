#!/usr/bin/env python 

import sys
import time
import struct
from ctypes import CFUNCTYPE
import os.path
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))

from libs import MacDbg
from libs.util import *
from libs.const import *

def generic_callback(info_struct):
    #turn info struct pointer into a dict 
    info_struct = dbg.exc_dict(info_struct.contents)

    print LOG("Breakpoint callback: @ rip == "),
    x = dbg.get_thread_state(info_struct["thread"])
    print hex(x["rip"])
    dbg.info_pretty_print(info_struct["thread"])

    #set state example
    #change first number to be printed out from 1 to be 99
    a = x["rip"] & 0x000000fff
    if a == 0xd90:
        x["rdi"] = 99
        dbg.set_thread_state(info_struct["thread"], x)

    return 1

def generic_callback_2(info_struct):
    print dbg.color_pink(LOG("FORK Callback"))
    raw_input("")
    return 1

def generic_callback_3(info_struct):
    print dbg.color_pink(LOG("EXEC Callback"))
    raw_input("")
    return 1

def generic_callback_4(info_struct):
    print dbg.color_red(LOG("EXIT Callback"))
    raw_input("")
    exit(-1)

def generic_callback_5(info_struct):
    print dbg.color_pink(LOG("SIGNAL Callback"))
    raw_input("")
    return 1

def generic_callback_9(info_struct):
    print dbg.color_red(LOG("OMG A CRASH"))
    raw_input("")
    #dbg.task_terminate(info_struct.contents.task);
    exit(1)


def debugger(dbg, kill = 0):
    try:
        prog_base_addr = dbg.base_address
        print "[+] Base address: " + hex(prog_base_addr)

        gen_callback = dbg.make_callback(generic_callback)

        #Breakpoint by address
        dbg.add_breakpoint(prog_base_addr+0xe3a, PERSISTENT, gen_callback)
        #Breakpoint by offset from base address
        dbg.add_breakpoint(0xeb6, PERSISTENT, gen_callback)
        #Breakpoint by name
        dbg.add_breakpoint("abc", PERSISTENT, gen_callback)
        #Breakpoint by name plus offset
        dbg.add_breakpoint("main", PERSISTENT, gen_callback, 62)

        dbg.list_breaks();

        gen_callback_2 = dbg.make_callback(generic_callback_2)
        gen_callback_3 = dbg.make_callback(generic_callback_3)
        gen_callback_4 = dbg.make_callback(generic_callback_4)
        gen_callback_5 = dbg.make_callback(generic_callback_5)
        gen_callback_9 = dbg.make_callback(generic_callback_9)

        dbg.add_exception_callback(gen_callback_9, EXC_BAD_ACCESS)

        # tracking process creation
        dbg.add_exception_callback(gen_callback_3, NOTE_EXEC)
        dbg.add_exception_callback(gen_callback_2, NOTE_FORK)
        dbg.add_exception_callback(gen_callback_5, NOTE_SIGNAL)
        dbg.add_exception_callback(gen_callback_4, NOTE_EXIT)

        dbg.disass(prog_base_addr, 4)


        print "CONTINUING"
        #start(task, infoPid);
        dbg.resume()
        time.sleep(10)
        dbg.detach(kill)
    except NameError as e:
    # except:
        # e = sys.exc_info()[0]
        print e
        raw_input("?")

if __name__ == "__main__":
    argv = sys.argv
    cmd = "./test_prog.app"
    dbg = MacDbg()

    if (len(argv) < 2):
        arr = (c_char_p * 2)()
        arr[0] = cmd
        arr[1] = 0

        dbg.run(arr[0], arr)
        pid = dbg.pid
    else:
        pid = int(argv[1])
        dbg.attach(pid)

    if dbg.task == 0:
        print "Failed to attach Check PID"
        exit(0)

    pid = dbg.pid
    print "[+] Attached to task # %s\n" % str(dbg.task)

    debugger(dbg, 1)

    dbg.terminate_()

    print "\n[+] Done!"
