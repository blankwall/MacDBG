#!/usr/bin/env python 


import sys
import time
import struct
import os
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))

from ctypes import *
from libs import MacDbg
from libs.util import *
from libs.const import *

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def debugger(dbg, infoPid, task, kill =0):
    dbg.suspend()
    prog_base_addr = dbg.base_address
    print "[+] Base_address: " + dbg.color_blue(hex(prog_base_addr))

  
    print "[+] SYMBOLS FOUND: "
    for i in dbg.parse.symbols_by_name.keys():
        print dbg.color_green(i),
    print

    print "[+] Memory map INFO: "
    for i in dbg.memory_map:
        print dbg.color_blue(hex(i.start_addr)) + " ",
        if i.region_type == 0: print  dbg.color_pink("TEXT"),
        elif i.region_type == 1: print dbg.color_pink("DATA"),
        elif i.region_type == 2: print dbg.color_pink("REGION") + str(i.region_detail),

        print dbg.color_white("PROT: ") + dbg.color_red(str(i.protection)),

        if i.name:
            print dbg.color_white("PATH: ") + dbg.color_green(i.name),
        print

    print "# of regions == " + str(len(dbg.memory_map))

    # GET PAGE PROTECTION TEST
    prot = dbg.get_page_protection(prog_base_addr)
    print "[+] PROTECTION FOR MAIN PAGE: "
    print dbg.color_red(prot)

    print "[+] THREAD LIST INFO::"
    threads = dbg.thread_list_info();
    for i in threads:
        if i:
            print "THREAD PORT #: " + dbg.color_pink(str(i)), "THREAD ID: " + dbg.color_yellow(str(dbg.get_thread_identifier_info(i).thread_id))

    thread = threads[0]
    print "Thread count:", dbg.color_pink(str(len(threads))), "Thread port:", dbg.color_pink(str(thread))


    print "[+] THREAD BASIC INFO::"
    basic_info = dbg.get_thread_basic_info(thread)
    print "user_time:", "sec:", dbg.color_pink(str(basic_info.user_time.seconds)), "microsec:", dbg.color_pink(str(basic_info.user_time.microseconds))
    print "sys_time:", "sec:", dbg.color_pink(str(basic_info.system_time.seconds)), "microsec:", dbg.color_pink(str(basic_info.system_time.microseconds))

    print "[+] THREAD IDENTIFIER INFO::"
    thread_ident_info = dbg.get_thread_identifier_info(thread)
    thread_id = thread_ident_info.thread_id
    thread_handle = thread_ident_info.thread_handle
    print "Thread id:", dbg.color_pink(str(thread_id)), "Thread_handle:", dbg.color_pink(str(thread_handle))


#BROKEN
    print "[+] GET PROC THREAD INFO::"
    proc_t_info = dbg.get_proc_threadinfo(thread_handle)
    print "pth User time:", dbg.color_pink(str(proc_t_info.pth_user_time)), "pth Sys time:", dbg.color_pink(str(proc_t_info.pth_system_time))
    print "pth priority:", dbg.color_pink(str(proc_t_info.pth_priority)), "pth max priority:", dbg.color_pink(str(proc_t_info.pth_maxpriority))

    print "Program pid == " + dbg.color_pink(str(dbg.find_pid()))

    region_info = dbg.get_region_info(prog_base_addr)
    print dbg.color_red(dbg.protection_to_string(region_info.protection))

    dbg.detach(kill)


if __name__ == "__main__":
    argv = sys.argv
    cmd = "./test_prog.app"
    dbg = MacDbg()
    run = 0
    # exit()
    if (len(argv) < 2):
        arr = (c_char_p * 2)()
        arr[0] = cmd
        arr[1] = 0

        dbg.run(arr[0], arr)
        pid = dbg.pid
        run = 1
    else:
        pid = int(argv[1])
        dbg.attach(pid)

    if dbg.task == 0:
        print "ATTACH FAILED :("
        exit(0)

    print "[+] Attached to task # %s\n" % str(dbg.task)

    raw_input("press enter to continue")
    dbg.reload()
    debugger(dbg, pid, dbg.task, run)

    dbg.terminate_()

    print "\n[+] Done!"
