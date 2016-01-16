from interface_commands import *
from py_libs.utils.util import *

from ctypes import *
import sys
from ctypes import *

from interface_commands import *
from libs.util import *

PROGRAM_RUNNING = False

# Command to function association
commands = {
    "info": info, "help": help,
    "run": run, "quit": quit, "detach": detach,
    "print": do_print, "attach": attach,
    "kill": kill, "process list": process_list,
    "break": set_break, "tbreak": set_temp_break,
    "examine": examine, "disassemble": disassemble,
    "x": examine, "clear": clear, "delete": delete,
    "continue": do_continue, "c": do_continue,
    "step": step, "next": next, "read_regs": read_regs,
    "write_regs": write_regs, "k": backtrace
}

# Given command string, determines what function to run
def interpret_command(dbg, cmd_line):
    global PROGRAM_RUNNING

    cmd = cmd_line.split(" ")
    command_params = cmd[1:]
    command_func = [c for c in commands.keys() if c.find(cmd[0]) == 0]
    single_char_cmd = [c for c in command_func if len(c) == 1]
    command_func = single_char_cmd if len(single_char_cmd) == 1 else command_func
    if len(command_func) == 0:
        ERR("Command not found: {0}".format(cmd[0]))
        return
    if len(command_func) > 1:
        ERR("Ambiguous command given: {0}, could match: {1}".format(cmd[0], ", ".join(command_func)))
        return

    command_func = command_func[0]
    cmd_ret = commands[command_func](dbg, command_params)
    if cmd_ret != None:
        PROGRAM_RUNNING = cmd_ret

# TODO: Handle ctrl+c: send sigint to program

def debug_shell():
    global PROGRAM_RUNNING

    debugger = MacDbg()

    while True:
        if not PROGRAM_RUNNING:
            cmd = raw_input("mdbg$ ")
            interpret_command(debugger, cmd)
        else:
            # Waiting for program to hit breakpoint
            pass

if __name__ == "__main__":
    debug_shell()
