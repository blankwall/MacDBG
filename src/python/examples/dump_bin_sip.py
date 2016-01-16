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


def debugger(dbg, kill = 0):
    dbg.suspend()
    prog_base_addr = dbg.base_address
    print "[+] Base address: " + hex(prog_base_addr)

    print hex(dbg.base_address)

    program = dbg.dump_binary()
    output = file("decrypt.bin", "w+").write(program)
    print "ALL DONE!"
    dbg.detach()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "USAGE [pid]"
        exit()

    pid = int(sys.argv[1])
    dbg = MacDbg()
    dbg.attach(pid)

    if dbg.task == 0:
        print "Failed to attach Check PID"
        exit(0)

    pid = dbg.pid
    print "[+] Attached to task # %s\n" % str(dbg.task)

    raw_input("press enter to continue")
    dbg.reload()
    debugger(dbg, 1)

