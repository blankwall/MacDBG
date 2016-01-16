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

#EXAMPLE SHOWING HOW TO WRITE TO AND READ FROM PROCESS MEMORY

def debugger(dbg, kill =0):

    prog_base_addr = dbg.base_address
    off = 0xf1e
    print hex(prog_base_addr)

    # ALLOCATION TEST
    allocation = dbg.allocate(0, 4096, 1); # returns allocation address
    allocation2 = dbg.allocate(0, 408342823492349896, 1) # should fail

    allocation3 = dbg.allocate_space(4096, VM_FLAGS_ANYWHERE)
    print "ALLOCATED PAGE @: " + dbg.color_green(hex(allocation3))

    dbg.write_bytes(allocation3, "AAAA")
    print "WRITING AAAA TO: " + dbg.color_green(hex(allocation3))
    
    cola = dbg.inject_code("HELLO")
    print "INJECTED HELLO" + " @: " + dbg.color_green(hex(cola))

    # dbg.write_memory(allocation, 0x41, 1)
    print "HEX DUMPING WRITTEN LOCATIONS"
    print  dbg.color_pink(dbg.hex_dump(allocation3, 10))
    print  dbg.color_pink(dbg.hex_dump(cola, 10))

    print "SEARCHING FROM: " + dbg.color_green(hex(allocation3-0x2000)) + " TO: " + dbg.color_green(hex(allocation3+0x2000))
    search_results = dbg.search_mem("HELLO", allocation3-0x2000, 0x4000)

    print "FOUND HELLO  @: "
    for i in search_results:
        print dbg.color_green(hex(i))

    # FREEING ALLOCATION TEST
    dbg.free_memory(allocation, 4096)

    # STRING SEARCH TEST
    search_string = "blue"
    search_results = dbg.search_string(search_string)

    print "FOUND blue"
    print "READING FOUND MEMORY"
    for i in search_results:
        print dbg.color_green(hex(i)), dbg.color_white(dbg.read_memory(i, 15))

    # BYTE SEARCH TEST
    print "FIRST 20 0x41 bytes found:"
    tm = 30
    search_byte = 0x41
    search_results = dbg.search_mem(search_byte, search_type=c_byte)
    for i in search_results:
        print dbg.color_green(hex(i)), dbg.color_pink(dbg.hex_dump(i, 10))
        tm -= 1
        if tm == 0: break

    dbg.detach(kill)

if __name__ == "__main__":
    argv = sys.argv
    cmd = "./test_prog.app"
    dbg = MacDbg()


    if (len(argv) < 2):
        arr = (c_char_p * 2)()
        arr[0] = cmd
        arr[1] = 0
        run = 1
        dbg.run(arr[0], arr)
        pid = dbg.pid
    else:
        pid = int(argv[1])
        dbg.attach(pid)
        run = 0

    if dbg.task == 0:
        print "FAILED TO ATTACH"
        exit(0)

    print "[+] Attached to task # %s\n" % str(dbg.task)

    debugger(dbg,run)

    print "\n[+] Done!"



