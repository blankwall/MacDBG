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
from subprocess import Popen, PIPE


# Scan system and check for libraries loaded at same base address 

def base_addr(dbg, name):

    if dbg.base_address == 0x100000000:
        print dbg.color_red("BASE ADDRESS == LOAD ADDRESS :( -- PID - " + str(dbg.pid) + " -  NAME " + name)

    dbg.detach()

if __name__ == "__main__":

    tmp = MacDbg()

    process = Popen(["ps", "aux"], stdout=PIPE)
    (output, err) = process.communicate()
    pids = output.split("\n")
    for i in pids:
        x = i.split()
        
        try:
            pid = x[1]
            name = x[10]
            name = name[name.find("/"):]
            tmp.attach(int(pid), 1)
        except:
            continue
        
        if tmp.task == 0:
            tmp.color_red("BAD PID CONTINUING")
            continue
        base_addr(tmp, name)

