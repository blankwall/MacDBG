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

# Search multiple programs at once put pids in file called pid

def search_mem(dbg, search):

    print dbg.color_white("BASE ADDRESS: " + hex(dbg.base_address))

    search_results = dbg.search_string(search, dbg.base_address, dbg.get_image_size()*1000)

    if len(search_results) > 0:
        for i in search_results:
            print dbg.color_green(hex(i)) + " --> " + dbg.color_pink(dbg.read_memory(i, 40))
        dbg.detach()
        return 1
    else:
        dbg.detach()
        return 0

if __name__ == "__main__":

    print "Usage ./search_multiple.py [search]"
    search = sys.argv[1]
    tmp = MacDbg()

    pids = file("pid").readlines()
    debuggers = []
    print tmp.color_red("Searching for string: " + search)
    count = 0
    for i in pids:
        print tmp.color_green("ATTACHING TO: " + str(int(i)))
        tmp.attach(int(i), 1)
        if tmp.task == 0:
            raw_input("????")
            tmp.color_red("BAD PID EXITING")
        x = search_mem(tmp, search)
        if x == 1:
            print tmp.color_pink("FOUND PROG PID = " + str(i))

