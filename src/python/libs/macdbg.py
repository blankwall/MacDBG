import sys
from ctypes import *
from const import *
from util import *
from parse.macho import *
from parse.BinaryData import *
from struct import pack
from math import ceil
from struct import pack, unpack
import string



# (function, argument type, return type)
cfuncs = (
          ("add_breakpoint"             , "c_uint, c_ulonglong, c_int, CFUNCTYPE(c_int, POINTER(ExcMsg))"   , "c_int"),
          ("add_exception_callback"     , "c_uint, CFUNCTYPE(c_int, POINTER(ExcMsg)), c_int"    , "c_int"),
          ("allocate"                   , "c_uint, c_ulonglong, c_size_t, c_int"        , "POINTER(c_ulonglong)"),
          ("attach"                     , "c_uint"                                      , "c_int"),
          ("allocate_space"             , "c_uint, c_ulong, c_uint"                     , "c_ulonglong"),
          ("change_page_protection"     , "c_uint, c_ulonglong, c_int"                  , "c_int"),
          ("continue_"                  , "c_uint"                                      , "c_uint"),
          ("detach"                     , "c_uint"                                      , "c_uint"),
          ("exception_to_string"        , "c_int"                                       , "c_char_p"),
          ("free_memory"                , "c_uint, c_ulonglong, c_size_t"               , "c_int"),
          ("find_pid"                   , "c_uint"                                      , "c_uint"),
          ("generic_callback"           , "POINTER(ExcMsg)"                             , "c_int"),
          ("get_dyld_map"               , "c_uint, POINTER(c_uint)"                     , "POINTER(POINTER(DyldInfo))"),
          ("get_base_address"           , "c_uint"                                      , "c_ulonglong"),
          ("get_image_size"             , "c_uint, c_ulonglong"                         , "c_ulonglong"),
          ("get_memory_map"             , "c_uint, c_ulonglong, POINTER(c_int)"         , "POINTER(POINTER(VmRegion))"),
          ("get_protection"             , "c_int"                                       , "c_char_p"),
          ("get_region_info"            , "c_uint, c_ulonglong"                         , "POINTER(VmRegionBasicInfo64)"),
          ("get_state"                  , "c_uint"                                      , "POINTER(X86ThreadState64)"),
          ("get_proc_threadinfo"        , "c_uint, c_ulonglong"                         , "POINTER(ProcThreadInfo)"),
          ("kqueue_loop"                , "c_int"                                       , "c_void_p"),
          ("list_breaks"                , "c_uint, POINTER(c_uint)"                     , "POINTER(c_ulong)"),
          ("print_byte"                 , "c_char_p"                                    , "None"),
          ("read_memory"                , "c_uint, c_ulonglong, c_size_t"               , "POINTER(c_char)"),
          ("read_memory_allocate"       , "c_uint, c_ulonglong, c_size_t"               , "POINTER(c_char)"),
          ("remove_all_breaks"          , "c_uint"                                      , "None"),
          ("remove_breakpoint"          , "c_uint, POINTER(BreakpointStruct)"           , "c_int"),
          ("remove_exception_callback"  , "c_int"                                       , "POINTER(ExceptionHandler)"),
          ("run"                        , "c_char_p, POINTER(c_char_p)"                 , "c_uint"),
          ("safe_malloc"                , "c_size_t"                                    , "c_void_p"),
          ("set_thread_state"           , "c_uint, POINTER(X86ThreadState64)"           , "c_int"),
          ("spawn_process"              , "c_char_p, POINTER(c_char_p)"                 , "c_int"),
          ("start"                      , "c_uint, c_uint"                              , "None"),
          ("suspend"                    , "c_uint"                                      , "None"),
          ("terminate_"                 , "c_uint"                                      , "c_int"),
          ("test"                       , "None"                                        , "None"),
          ("thread_count"               , "c_uint"                                      , "c_uint"),
          ("thread_list_info"           , "c_uint, POINTER(POINTER(c_void_p)), POINTER(c_int)"  , "c_int"),
          ("get_thread_basic_info"      , "c_uint"                                      , "POINTER(ThreadBasicInfo)"),
          ("get_thread_identifier_info" , "c_uint"                                      , "POINTER(ThreadIdentInfo)"),
          ("thread_state"               , "c_uint, c_uint"                              , "POINTER(X86ThreadState64)"),
          ("write_memory"               , "c_uint, c_ulong, c_ulong, c_ulonglong"       , "None"),
          ("get_page_protection"        , "c_uint, c_ulonglong"                         , "c_char_p"),
          ("inject_code"                , "c_uint, c_char_p, c_uint"                    , "c_ulonglong"),
          ("write_bytes"                , "c_uint, c_ulonglong, c_char_p, c_uint"       , "c_ulonglong"),
          ("thread_resume_"             , "c_uint"                                      , "c_uint"),
          ("thread_suspend_"            , "c_uint"                                      , "c_uint"),
          ("thread_terminate_"          , "c_uint"                                      , "c_uint")
         )

def add_cfunc(c_types):
    """Exec strings of adding ctype functions, arg, and ret types"""
    # (MacDbg.C_attach = MacDbg.lib.attach, MacDbg.C_attach.argtypes = [c_uint, c_int], MacDbg.C_attach.restype = c_int)
    function = c_types[0]
    argument = '[' + c_types[1] + ']' if c_types[1] != 'None' else c_types[1]
    ret_type = c_types[2]

    try:
        exec("MacDbg.C_{0} = MacDbg.lib.{0}".format(function)) in globals(), locals()
        exec("MacDbg.C_{0}.argtypes = {1}".format(function, argument)) in globals(), locals()
        exec("MacDbg.C_{0}.restype = {1}".format(function, ret_type)) in globals(), locals()
    except Exception, ex:
        ERR("%s in executing function: %s" % (ex, function))
        err_cont()

class MemoryLayout:
    def __init__(self):
        self.start_addr = 0
        self.end_addr = 0
        self.size = 0
        self.name = None
        self.region_type = None
        self.protection = ""
        self.region_detail = ""

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Breakpoint():
    def __init__(self, dbg):
        self.dbg = dbg
        self.callback_table = {}

    def register_breakpoint(self, address, callback):
        self.callback_table[address] = callback

    def dispatch(self, info_struct):
        x = self.dbg.get_thread_state(info_struct.contents.thread)
        try:
            return self.callback_table[x["rip"]](info_struct)
        except KeyError:
            print "NO REGISTERED BREAKPOINT PASSING TO KERNEL :("
            return -1


class MacDbg:
    """
    Python wrappers for C functions exported in libmcdb.dylib using CTYPES.
    Refer to macdbg_test.py for example usage of functions, structs, and enums
    """

    ## Class variables ##
    active = 0
    lib = CDLL("libmcdb.dylib")

    def __init__(self, pid=None):
        """
        Add C functions using Ctypes (predefined strings in a tuple) as a class variable.
        task can be retrieved as class variable ([var].task) or return from attach function.
        """
        self.pid = pid
        self.task = None
        self.base_address = None
        self.dyld_map = None
        self.no_of_dyld = None
        self.load_address = 0x100000000
        self.memory_map = []
        self.make_callback = CFUNCTYPE(c_int, POINTER(ExcMsg))
        self.libraries = {}
        self.break_p = Breakpoint(self)
        self.generic_callback = self.make_callback(self.break_p.dispatch)


        if not MacDbg.active:
            MacDbg.active = 1
            map(add_cfunc, cfuncs)

        if pid:
            self.task = self.attach(self.pid)
            if self.task == 0:
                print "[-] failed to attach -- check pid"

    def color_red(self, text):
        return bcolors.FAIL + text + bcolors.ENDC 
    def color_blue(self, text):
        return bcolors.OKBLUE + text + bcolors.ENDC 
    def color_green(self, text):
        return bcolors.OKGREEN + text + bcolors.ENDC 
    def color_yellow(self, text):
        return bcolors.WARNING + text + bcolors.ENDC 
    def color_pink(self, text):
        return bcolors.HEADER + text + bcolors.ENDC 
    def color_white(self, text):
        return bcolors.BOLD + text + bcolors.ENDC 
    def color_underline(self, text):
        return bcolors.UNDERLINE + text + bcolors.ENDC 

    def check_is_mapped(self, addr):
        for i in self.memory_map:
            if addr > i.start_addr and addr < i.end_addr:
                return True
        return False

    def check_address(self, addr):
        return self.get_page_protection(addr)

    def color_code(self,addr):
        prot = self.check_address(addr)
        if prot == "r-x":
            return self.color_pink(hex(addr))
        else:
            return self.color_blue(hex(addr))
        
    def return_info(self, addr):
        if self.check_is_mapped(addr):
            x = self.check_address(addr)
            if x == "r-x":
                return self.color_code(addr)
            else:
                k = struct.unpack("<q", self.read_memory(addr, 8))
                ret = self.color_code(addr)  + " --> "
                if self.check_is_mapped(k[0]):
                    ret += self.color_code(k[0])
                else:
                    ret += hex(k[0])
                return ret

        else:
            return hex(addr)

    def stack_trace(self, rsp):
        ret  = self.return_info(rsp) +"\n"
        ret += self.return_info(rsp+8) +"\n"
        ret += self.return_info(rsp+16) +"\n"
        ret += self.return_info(rsp+24) +"\n"
        
        return ret
            
    def info_pretty_print(self, thread):
        x = self.get_thread_state(thread)
        print bcolors.FAIL + "RAX: " + bcolors.ENDC + self.return_info(x["rax"])
        print bcolors.FAIL + "RBX: " + bcolors.ENDC + self.return_info(x["rbx"])
        print bcolors.FAIL + "RCX: " + bcolors.ENDC + self.return_info(x["rcx"])
        print bcolors.FAIL + "RDX: " + bcolors.ENDC + self.return_info(x["rdx"])
        print bcolors.FAIL + "RSI: " + bcolors.ENDC + self.return_info(x["rsi"])
        print bcolors.FAIL + "RDI: " + bcolors.ENDC + self.return_info(x["rdi"])
        print bcolors.FAIL + "RBP: " + bcolors.ENDC + self.return_info(x["rbp"])
        print bcolors.FAIL + "RSP: " + bcolors.ENDC + self.return_info(x["rsp"])
        print bcolors.FAIL + "RIP: " + bcolors.ENDC + self.return_info(x["rip"])
        print "-"*20
        self.disass(x["rip"], 6)
        print "-"*20
        print self.stack_trace(x["rsp"])
        return

#REWRITE THESE
    def load_symbols(self):
        no_of_dyld = c_uint32()
        self.dyld_map = self.get_dyld_map(byref(no_of_dyld))
        self.no_of_dyld = no_of_dyld.value

        prog_data = self.dump_binary()

        try:
            binary = BinaryData(prog_data)
            self.parse = MachOFile(binary)
        except:
            print "[-] Failed parsing symbols"
            self.parse = None   

    def load_library_symbols(self, addr, size):
        pages = ceil(size / 4096.0) * 2
        # print "BINARY IS %d PAGES" % pages

        print "PAGES = " + str(pages)
        i = 0
        prog_data = ""
        page = 4096
        while i < pages:
            mem = self.read_memory(addr+(i*page), page)
            if mem == 0:
                print "READ MEM FAILED"
            prog_data += mem
            i += 1

        try:
            binary = BinaryData(prog_data)
            parse = MachOFile(binary)
        except:
            print "[-] Failed parsing symbols"

        return parse.symbols_by_name
            # self.parse = None   

    def load_memory_map(self):
        dyld_infos = self.dyld_map 
        no_of_dyld = self.no_of_dyld
        for i in range(no_of_dyld):
            tmp = MemoryLayout()
            tmp.start_addr = dyld_infos[i].contents.start_addr
            tmp.end_addr  = dyld_infos[i].contents.end_addr
            tmp.region_type  = dyld_infos[i].contents.region_type
            tmp.size  = dyld_infos[i].contents.size
            tmp.name  = dyld_infos[i].contents.path
            tmp.protection = self.protection_to_string(dyld_infos[i].contents.protection)
            self.memory_map.append(tmp)

        region_count = c_int()
        vm_reg = self.get_memory_map(self.base_address, byref(region_count))
        region_count = region_count.value
        count = 0

        for i in self.memory_map:
            tmp = vm_reg[count].contents.address_start
            if tmp == i.start_addr:
                i.protection = self.protection_to_string(vm_reg[count].contents.protection)

            elif tmp < i.start_addr:
                while tmp < i.start_addr and count < region_count - 2:
                    k = MemoryLayout()
                    k.start_addr = vm_reg[count].contents.address_start
                    k.end_addr = vm_reg[count].contents.address_end
                    k.protection = self.protection_to_string(vm_reg[count].contents.protection)
                    k.region_type = 2
                    self.memory_map.insert(count, k)
                    count += 1
                    tmp = vm_reg[count].contents.address_start

            count += 1
            if count > region_count-1:
                break

    def list_libraries(self):
        dyld_infos = self.dyld_map 
        no_of_dyld = self.no_of_dyld

        for i in range(no_of_dyld):
            dyld_start = dyld_infos[i].contents.start_addr
            dyld_end   = dyld_infos[i].contents.end_addr
            dyld_type  = dyld_infos[i].contents.region_type
            dyld_size  = dyld_infos[i].contents.size
            dyld_path  = dyld_infos[i].contents.path
            print hex(dyld_start), hex(dyld_end), "TEXT" if dyld_type == 0 else "DATA", dyld_size/1024, dyld_path

    def find_pid(self):
        return MacDbg.C_find_pid(self.task)

    def dict_state(self, state):
        """
        Takes X86ThreadState64 struct and returns register state values in a dictionary
        """
        if type(state).__name__ != "X86ThreadState64":
            ERR("Argument type %s must be %s" %
                (type(state).__name__, type(X86ThreadState64).__name__))
            return 0

        return dict([('rax', state.rax), ('rbx', state.rbx), ('rcx', state.rcx),
                     ('rdx', state.rdx), ('rdi', state.rdi), ('rsi', state.rsi),
                     ('rbp', state.rbp), ('rsp', state.rsp), ('r8', state.r8),
                     ('r9', state.r9), ('r10', state.r10), ('r11', state.r11),
                     ('r12', state.r12), ('r13', state.r13), ('r14', state.r14),
                     ('r15', state.r15), ('rip', state.rip), ('rflags', state.rflags),
                     ('cs', state.cs), ('fs', state.fs), ('gs', state.gs)])

    def dict_break(self, state):
        x = X86ThreadState64()
        x.rax = state["rax"];x.rbx = state["rbx"];x.rcx = state["rcx"];x.rdx = state["rdx"];x.rdi = state["rdi"];x.rsi = state["rsi"]
        x.rbp = state["rsp"];x.rsp = state["rsp"];x.r8 = state["r8"];x.r9 = state["r9"];x.r10 = state["r10"];x.r11 = state["r11"]
        x.r12 = state["r12"];x.r13 = state["r13"];x.r14 = state["r14"];x.r15 = state["r15"];x.rip = state["rip"];x.rflags = state["rflags"]
        x.cs = state["cs"];x.fs = state["fs"];x.gs = state["gs"]
        return x

    def exc_dict(self, info_struct):
        if type(info_struct) != ExcMsg:
            print "ERR type must be ExcMsg"
            return
        return dict([('exception_port', info_struct.exception_port), ('thread', info_struct.thread), ('task', info_struct.thread),
                     ('exception', info_struct.exception), ('code', info_struct.code), ('codeCnt', info_struct.codeCnt)])

    def disass(self, addr, ins, ret=0):
        """
        Print ins amount of instructions at address -- Requires capstone
        """
        try:
            import capstone
        except:
            ERR(" Missing Capstone library (pip install capstone)")
            return 0

        if ins < 0:
            ERR("Number of instructions must be more than 0! You entered %d" % ins)
            return 0

        tmp = ins
        ins *= 12
        CODE = self.read_memory(addr, ins)
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        arr = []
        for (address, size, mnemonic, op_str) in md.disasm_lite(CODE, addr):
            if ret == 0:
                print  self.color_pink(hex(address)),
                print  bcolors.FAIL + mnemonic + bcolors.ENDC,
                print  bcolors.OKGREEN + op_str + bcolors.ENDC
            else:
                arr.append("0x%x:\t%s\t%s" % (address, mnemonic, op_str))

            tmp -= 1
            if tmp == 0:
                break
        return arr

    def dump_binary(self):
        size = self.get_image_size()*2
        pages = ceil(size / 4096.0)
        # print "BINARY IS %d PAGES" % pages

        i = 0
        prog_data = ""
        page = 4096
        while i < pages:
            mem = self.read_memory(self.base_address+(i*page), page)
            if mem == 0:
                print "READ MEM FAILED"
            prog_data += mem
            i += 1
        return prog_data

    def protection_to_string(self, prot):
        prot_str = ""
        if(prot & VM_PROT_READ ):
            prot_str += "r"
        else:
            prot_str += "-"
        if(prot & VM_PROT_WRITE ):
            prot_str += "w"
        else:
            prot_str += "-"
        if(prot & VM_PROT_EXECUTE ):
            prot_str += "x"
        else:
            prot_str += "-"
        return prot_str

    def search_from_addr(self, search, start_addr, size):
        max_finds = 1000
        cur_addr = start_addr
        read_chunk_size = 15000
        size_read = 0
        found = []
        find_idx = 0

        try:
            while True:
                if size - size_read < read_chunk_size:
                    read_chunk_size = size - size_read

                memory = self.read_memory(cur_addr, read_chunk_size)
                # Hack: triggers execption for null pointer
                memory[0]
                # memory = string_at(memory, read_chunk_size)
                size_read += read_chunk_size

                if (size == -1 and memory == None) or len(found) > max_finds:
                    break

                while len(found) < max_finds:
                    find_idx = memory.find(search, find_idx)
                    if find_idx == -1:
                        break
                    found.append(cur_addr + find_idx)
                    find_idx += len(search)

                if size_read == size:
                    break

                cur_addr += read_chunk_size

        except Exception, ex:
            pass

        return found

    # def search_all_mem(self, search):
    #     found = []

    #     for region in self.memory_map:
    #         region_start = region.start_addr
    #         region_size = region.size
    #         region_finds = self.search_from_addr(search, region_start, region_size)
    #         found.extend(region_finds)
    #     return found

    def search_all_mem(self, search):
        found = []
        region_count = c_int()
        vm_reg = self.get_memory_map(self.get_base_address(), byref(region_count))

        region_count = region_count.value

        for i in range(region_count):
            region_start = vm_reg[i].contents.address_start
            region_size = vm_reg[i].contents.size
            region_finds = self.search_from_addr(search, region_start, region_size)
            found.extend(region_finds)
        return found

    def search_mem(self, search, start_addr=-1, size=-1, search_type=None):
        if search_type != None:
            if type(search_type) is not str:
                if search_type not in SEARCH_TYPES.keys():
                    ERR("Unable to find search type")
                    return
                else:
                    search_type = SEARCH_TYPES[search_type]
            search = pack("<{0}".format(search_type), search)
        elif type(search) is int:
            search = pack("<Q", search) if search > 0 else pack("<q", search)
        elif type(search) is str:
            pass
        else:
            ERR("No valid search type was given or found")
            return

        if start_addr == -1 and size == -1:
            return self.search_all_mem(search)

        if start_addr == -1:
            start_addr = self.base_address

        return self.search_from_addr(search, start_addr, size)


    ################
    ## C Wrappers ##
    ################

    def add_breakpoint(self, patch_addr, cont, callback, offset = 0):

        if type(patch_addr) == int or type(patch_addr) == long:
            if patch_addr < self.base_address:
                patch_addr += self.base_address

            self.break_p.register_breakpoint(patch_addr, callback)
            return MacDbg.C_add_breakpoint(self.task, patch_addr, cont, self.generic_callback)
        elif type(patch_addr) == str:
            func = ""
            for i in self.parse.symbols_by_name:
                if patch_addr == i[1:]:
                    func = i
                    break
            if func == "":
                return 0

            func_offset = self.parse.symbols_by_name[i] - self.load_address
            break_addr = func_offset + self.base_address + offset
            if "PLT" in func:
                break_addr = struct.unpack("<q", self.read_memory(break_addr, 8))[0]

            self.break_p.register_breakpoint(break_addr, callback)
            return MacDbg.C_add_breakpoint(self.task, break_addr, cont, self.generic_callback)
        else:
            return 0

    def add_breakpoint_library(self, lib_name, patch_addr, cont, callback, offset = 0):
        if self.no_of_dyld == None:
            no_of_dyld = c_uint32()
            self.dyld_map = self.get_dyld_map(byref(no_of_dyld))
            self.no_of_dyld = no_of_dyld.value
        dyld_infos = self.dyld_map 
        no_of_dyld = self.no_of_dyld

        for i in range(no_of_dyld):
            dyld_path  = dyld_infos[i].contents.path
            name = dyld_path[dyld_path.rfind("/")+1:]
            if name == lib_name:
                break

        dyld_start = dyld_infos[i].contents.start_addr
        dyld_end   = dyld_infos[i].contents.end_addr
        dyld_type  = dyld_infos[i].contents.region_type
        dyld_size  = dyld_infos[i].contents.size
        dyld_path  = dyld_infos[i].contents.path
        print hex(dyld_start), hex(dyld_end), "TEXT" if dyld_type == 0 else "DATA", dyld_size/1024, dyld_path

        if type(patch_addr) == int or type(patch_addr) == long:
            if patch_addr < dyld_start:
                patch_addr += dyld_start

            self.break_p.register_breakpoint(patch_addr, callback)
            return MacDbg.C_add_breakpoint(self.task, patch_addr, cont, self.generic_callback)
        elif type(patch_addr) == str:
            if lib_name in self.libraries.keys():
                symbols = self.libraries[lib_name]
            else:
                size = dyld_infos[i].contents.end_addr - dyld_infos[i].contents.start_addr 
                symbols = self.load_library_symbols(dyld_infos[i].contents.start_addr, size)
                self.libraries[lib_name] = symbols

            found = False
            for i in symbols:
                if patch_addr == i[1:]:
                    found = True
                    break
            if not found:
                return 0

            func_offset = symbols[i]
            break_addr = func_offset + dyld_start + offset

            print hex(func_offset)

            print hex(break_addr)
            print self.hex_dump(break_addr,10)

            self.break_p.register_breakpoint(break_addr, callback)
            return MacDbg.C_add_breakpoint(self.task, break_addr, cont, self.generic_callback)
        else:
            return 0


    def make_callback(self, func):
        CALLBKFUNC = CFUNCTYPE(c_int, POINTER(ExcMsg))
        return CALLBKFUNC(func)

    def add_exception_callback(self, callback, exception):
        return MacDbg.C_add_exception_callback(self.task, callback, exception)

    def allocate(self, patch_addr, size, flags):
        allocation = MacDbg.C_allocate(self.task, patch_addr, size, flags)
        if not allocation:
            return 0
        return allocation.contents.value

    def attach(self, infoPid, light=-1):
        """Attach to a process via PID. Return instance of task"""

        self.pid = infoPid
        self.task = MacDbg.C_attach(infoPid)
        if self.task == 0:
          return self.task
        self.base_address = self.get_base_address()
        if light == -1:
            self.load_symbols()
            self.load_memory_map()
        return self.task

    def change_page_protection(self, patch_addr, new_protection):
        return MacDbg.C_change_page_protection(self.task, patch_addr, new_protection)

    def resume(self):
        self.task = MacDbg.C_continue_(self.task)
        return None

    def detach(self, kill=0):
        if kill == 1:
            return self.terminate_()
        else:
            return MacDbg.C_detach(self.task)

    def exception_to_string(self, exc):
        """Return a string of ext exception enum argument"""
        return MacDbg.C_exception_to_string(exc)

    def free_memory(self, address, size):
        return MacDbg.C_free_memory(self.task, address, size)

    def generic_callback(self, info_struct):
        MacDbg.C_generic_callback(info_struct)
        return None

    def get_base_address(self):
        return MacDbg.C_get_base_address(self.task)


    def get_memory_map(self, address, int_point):
        return MacDbg.C_get_memory_map(self.task, address, int_point)

    def get_protection(self, protection):
        return MacDbg.C_get_protection(protection)

    def get_region_info(self, address):
        x = MacDbg.C_get_region_info(self.task, address)
        if x:
            return x.contents
        return None

    def get_thread_state(self, thread):
        """Return register states from thread in a X86ThreadState64 struct"""
        x = MacDbg.C_get_state(thread)
        return self.dict_state(x.contents)

    def hex_dump(self, addr, size, color=1):
        CODE = self.read_memory(addr, size)
        return  ":".join("{:02x}".format(ord(c)) for c in CODE)

    def kqueue_loop(self, kp):
        return MacDbg.C_kqueue_loop(kp)

    def list_breaks(self):
        count = c_uint()
        x = MacDbg.C_list_breaks(self.task, count)
        index = 0
        while index < count.value:
            print "[%d] " % index +  hex(x[index]) 
            index += 1

        return None

    def get_breaks(self):
        count = c_uint()
        x = MacDbg.C_list_breaks(self.task, count)
        index = 0
        ret = []
        while index < count.value:
            ret.append(x[index])
            index += 1
        return ret

    def print_byte(self, byte):
        MacDbg.C_print_byte(byte)
        return None

    def read_memory_string(self,address, size):
        memory = string_at(MacDbg.C_read_memory(self.task, address, size),size)
        try:
            memory[0]
        except:
            return 0
        return memory

    def read_memory(self, address, size):
        memory = string_at(MacDbg.C_read_memory(self.task, address, size),size)
        try:
            memory[0]
        except:
            return 0
        return memory

    def read_memory_allocate(self, address, size):
        memory = MacDbg.C_read_memory_allocate(self.task, address, size)
        try:
            memory[0]
        except:
            return 0
        return memory

    def remove_all_breaks(self):
        self.break_p.callback_table = {}
        MacDbg.C_remove_all_breaks(self.task)
        return None

    def remove_breakpoint(self, breakpoint):
        del self.break_p.callback_table[breakpoint]
        return MacDbg.C_remove_breakpoint(self.task, breakpoint)

    def remove_exception_callback(self, exc):
        return MacDbg.C_remove_exception_callback(exc)

    def reload(self):
        self.base_address = self.get_base_address()        
        self.pid = self.find_pid()
        self.load_symbols()
        self.load_memory_map()

    def run(self, command, args):
        self.task = MacDbg.C_run(command, args)
        if self.task == 0:
          return self.task
        self.base_address = self.get_base_address()        
        self.pid = self.find_pid()
        self.load_symbols()
        self.load_memory_map()
       
        return self.task

    def safe_malloc(self, x):
        return MacDbg.C_safe_malloc(x)

    def set_thread_state(self, thread, break_state):
        if type(break_state) == dict:
            break_state = self.dict_break(break_state)

        return MacDbg.C_set_thread_state(thread, break_state)

    def spawn_process(self, command, args):
        return MacDbg.C_spawn_process(command, args)

    def terminate_(self):
        return MacDbg.C_terminate_(self.task)

    def test(self):
        """Test function"""
        MacDbg.C_test()
        return None

    def thread_count(self):
        return MacDbg.C_thread_count(self.task)

    def thread_state(self, thread_count):
        return MacDbg.C_thread_state(self.task, thread_count)

    def get_thread_basic_info(self, thread):
        x = MacDbg.C_get_thread_basic_info(thread)
        if x:
            return x.contents
        return None

    def get_thread_identifier_info(self, thread):
        x = MacDbg.C_get_thread_identifier_info(thread)
        if x:
            return x.contents
        return None

    def thread_list_info(self):
        tc = c_int()
        tlp = POINTER(c_void_p)()

        MacDbg.C_thread_list_info(self.task, tlp, tc)
        threadlist = []
        for i in range(tc.value):
            threadlist.append(tlp[i])
        return threadlist

    def start(self, infoPid):
        return MacDbg.C_start(self.task, infoPid)

    def suspend(self):
        return MacDbg.C_suspend(self.task)

    def write_memory(self, address, data, length):
        MacDbg.C_write_memory(self.task, address, data, length)
        return None
        
    def get_dyld_map(self, count_p):
        return MacDbg.C_get_dyld_map(self.task, count_p)

    def get_page_protection(self, address):
        return MacDbg.C_get_page_protection(self.task, address)

    def inject_code(self, code):
        return MacDbg.C_inject_code(self.task, code, len(code))

    def allocate_space(self, size, flags):
        return MacDbg.C_allocate_space(self.task, size, flags)

    def write_bytes(self, address, byters):
        return MacDbg.C_write_bytes(self.task, address, byters, len(byters))

    def get_image_size(self):
        return MacDbg.C_get_image_size(self.task, self.base_address)

    def get_proc_threadinfo(self, thread_handle):
        if self.pid == None:
            self.pid = self.find_pid()
        x = MacDbg.C_get_proc_threadinfo(self.pid, thread_handle)
        if x:
            return x.contents
        return None

    def thread_resume_(self, thread):
        return MacDbg.C_thread_resume_(thread)

    def thread_suspend_(self, thread):
        return MacDbg.C_thread_suspend_(thread)

    def thread_terminate_(self, thread):
        return MacDbg.C_thread_terminate_(thread)

    def strings(self, prog, min=4):
        result = ""
        for i in range(len(prog)):
            c = prog[i]
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield (result,(i-len(result)))
            result = ""


    def search_string(self, search, start_addr=-1, size=-1):
        if type(search) != str:
            return None
        

        mem = False
        if size == -1:
            size = self.get_image_size()*2
            mem = True
        if start_addr == -1:
            start_addr = self.base_address
        pages = ceil(size / 4096.0)

        i = 0
        prog_data = ""
        page = 4096
        while i < pages:
            mem = self.read_memory(self.base_address+(i*page), page)
            if mem == 0:
                print "READ MEM FAILED"
            prog_data += mem
            i += 1

        if mem == False:
          region_count = c_int()
          vm_reg = self.get_memory_map(self.get_base_address(), byref(region_count))
          region_count = region_count.value

          for i in range(region_count):
              region_start = vm_reg[i].contents.address_start
              region_size = vm_reg[i].contents.size
              mem = self.read_memory(region_start, region_size) 
              if mem == 0:
                  print "READ MEM FAILED"           
              prog_data += mem

        # print "SEARCHING %d PAGES" % (len(prog_data)/page)
        found = []
        for i in self.strings(prog_data):
            # print i[0]
            if search in i[0]:
                found.append(i[1]+self.base_address)



           
        return found

