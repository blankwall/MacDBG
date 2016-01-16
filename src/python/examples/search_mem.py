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

# Generic string searcing progrma

def debugger(dbg, search):

    print hex(dbg.base_address)

    search_results = dbg.search_string(search, dbg.base_address, dbg.get_image_size()*1000)

    print "Searching memory...."
    for i in search_results:
        print dbg.color_green(hex(i)) + " --> " + dbg.color_pink(dbg.read_memory(i, 200))

    print "Done"
    dbg.detach()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print "USAGE [pid] [search_string]"
        exit()
    dbg = MacDbg()

    pid = int(sys.argv[1])
    dbg.attach(pid)

    if dbg.task == 0:
        exit(0)

    print "[+] Attached to task # %s\n" % str(dbg.task)

    debugger(dbg, sys.argv[2])

    print "\n[+] Done!"
