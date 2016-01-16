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

#MALLOC TRACER FOR FIREFOX ATTACH TO FIREFOX AND IT WILL HOOK ON ALL MALLOCS AND SHOW RETURN ADDRESSES 
#WARNING THIS IS SLOW MALLOC IS CALLED A LOT

def ret_callback(info):
    x = dbg.get_thread_state(info.contents.thread)
    print dbg.color_white(" RETURN --> " ),
    print dbg.color_yellow(hex(x["rax"]))
    return 1

def generic_callback(info_struct):
    x = dbg.get_thread_state(info_struct.contents.thread)
    size = x["rdi"]
    k = struct.unpack("<q", dbg.read_memory(x["rsp"], 8))
    print dbg.color_pink("MALLOC CALLED FOR SIZE: "),
    print dbg.color_green(hex(size)),
    dbg.add_breakpoint(k[0], ONE_TIME, ret_callback)

    return 1

def debugger(dbg, infoPid, task, kill = 0):
    dbg.suspend()
    prog_base_addr = dbg.base_address
    print "[+] Base address: " + hex(prog_base_addr)

    dbg.add_breakpoint_library("libmozglue.dylib", "moz_xmalloc", PERSISTENT, generic_callback)
    dbg.resume()
    while(1): continue



if __name__ == "__main__":
    argv = sys.argv
    cmd = "./test_prog.app"
    dbg = MacDbg()

    pid = int(argv[1])
    dbg.attach(pid, 1)

    if dbg.task == 0:
        print "Failed to attach Check PID"
        exit(0)

    pid = dbg.pid
    print "[+] Attached to task # %s\n" % str(dbg.task)

    debugger(dbg, pid, dbg.task, 1)

