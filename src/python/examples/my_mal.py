#!/usr/bin/env python 

import sys
import time
import struct
import os.path
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))

from libs import MacDbg
from libs.util import *
from libs.const import *

#FOR USE WITH THE EXAMPLE MALLOC.C PROGRAM OR ANY PROGRAM THAT WITH THE SYMBOL _malloc@PLT

def ret_callback(info):
    x = dbg.get_thread_state(info.contents.thread)
    print dbg.color_white(" RETURN --> " ),
    print dbg.color_yellow(hex(x["rax"]))
    return 1

def generic_callback(info_struct):
    x = dbg.get_thread_state(info_struct.contents.thread)
    size = x["rdi"]
    print
    k = struct.unpack("<q", dbg.read_memory(x["rsp"], 8))
    print dbg.color_pink("MALLOC CALLED FOR SIZE: "),
    print dbg.color_green(hex(size)),
    # print hex(k)
    dbg.add_breakpoint(k[0], ONE_TIME, ret_callback)
    return 1

def mal_break(info_struct):
    x = dbg.get_thread_state(info_struct.contents.thread)
    print "OMG ARE YOU SERIOUS???? " + hex(x["rip"]) + " " + hex(x["rdi"])
    return 1

def debugger(dbg, infoPid, task, kill = 0):
    dbg.suspend()
    prog_base_addr = dbg.base_address
    print "[+] Base address: " + hex(prog_base_addr)


    #SHOWING HOW TO GET THE REAL ADDRESS FROM THE PLT

    print dbg.parse.symbols_by_name
    x = dbg.parse.symbols_by_name["_malloc@PLT"]
    x -= dbg.load_address
    x += dbg.base_address

    print hex(x)
    print dbg.hex_dump(x, 10)
    l = struct.unpack("<q", dbg.read_memory(x, 8))[0]
    print "MAL ADDRESS: " + hex(l)

    #BUT ITS NOT NEEDED WITH SYMBOLS
    dbg.add_breakpoint("malloc@PLT", PERSISTENT, mal_break)


    print "RESUMING TASK"
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

    dbg.load_symbols()
    pid = dbg.pid
    print "[+] Attached to task # %s\n" % str(dbg.task)

    debugger(dbg, pid, dbg.task, 1)

