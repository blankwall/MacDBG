"""
Structs, defines, and enums defined in C code. 
"""
from ctypes import Structure, c_byte, c_ubyte, c_char, c_char_p, c_short, c_ushort, c_int, c_uint, c_int64, \
                   c_float, c_double, c_long, c_ulong, c_longlong, c_ulonglong, POINTER

"""
Structs and definitions
"""
# Ctype structure for exc_msg_t
class ExcMsg(Structure):
    _fields_ = [("exception_port"   , c_uint),
                ("thread"           , c_uint),
                ("task"             , c_uint),
                ("exception"        , c_int),
                ("code"             , c_int64),
                ("codeCnt"          , c_uint)]

# Ctype structure for x86_thread_state64_t
class X86ThreadState64(Structure):
    _fields_ = [("rax"      , c_ulonglong),
                ("rbx"      , c_ulonglong),
                ("rcx"      , c_ulonglong),
                ("rdx"      , c_ulonglong),
                ("rdi"      , c_ulonglong),
                ("rsi"      , c_ulonglong),
                ("rbp"      , c_ulonglong),
                ("rsp"      , c_ulonglong),
                ("r8"       , c_ulonglong),
                ("r9"       , c_ulonglong),
                ("r10"      , c_ulonglong),
                ("r11"      , c_ulonglong),
                ("r12"      , c_ulonglong),
                ("r13"      , c_ulonglong),
                ("r14"      , c_ulonglong),
                ("r15"      , c_ulonglong),
                ("rip"      , c_ulonglong),
                ("rflags"   , c_ulonglong),
                ("cs"       , c_ulonglong),
                ("fs"       , c_ulonglong),
                ("gs"       , c_ulonglong)]

# Ctype structure for breakpoint_struct
class BreakpointStruct(Structure):
    _fields_ = [("original" , c_ulonglong),
                ("address"  , c_ulonglong),
                ("handler"  , c_ulong),
                ("flags"    , c_int)]

# Ctype structure for exception_handler
class ExceptionHandler(Structure):
    _fields_ = [("exception", c_int),
                ("handler"  , c_ulong)]

# Ctype structure for vm_region_basic_info_data_64_t
class VmRegionBasicInfo64(Structure):
    _fields_ = [("protection"       , c_int),
                ("max_protection"   , c_int),
                ("inheritance"      , c_uint),
                ("shared"           , c_uint),
                ("reserved"         , c_uint),
                ("offset"           , c_ulonglong),
                ("behavior"         , c_int),
                ("user_wired_count" , c_ushort)]

# Ctype structure for vm_region_t
class VmRegion(Structure):
    _fields_ = [("region_type"      , c_uint),
                ("address_start"    , c_ulonglong),
                ("address_end"      , c_ulonglong),
                ("size"             , c_ulonglong),
                ("protection"       , c_uint),
                ("max_protection"   , c_uint),
                ("share_mode"       , c_uint),
                ("region_detail"    , c_char_p)]


#Ctype structure for dyld_info_struct
class DyldInfo(Structure):
    _fields_ = [("start_addr"       , c_ulonglong),
                ("end_addr"         , c_ulonglong),
                ("region_type"      , c_uint),
                ("size"             , c_ulonglong),
                ("path"             , c_char_p),
                ("protection"       , c_uint)]

class time_value_t(Structure):
    _fields_ = [("seconds"          , c_int),
                ("microseconds"     , c_int)]

#Ctype structure for thread_basic_info_t
class ThreadBasicInfo(Structure):
    _fields_ = [("user_time"        , time_value_t),
                ("system_time"      , time_value_t),
                ("cpu_usuage"       , c_int),
                ("policy"           , c_int),
                ("run_state"        , c_int),
                ("flags"            , c_int),
                ("suspend_count"    , c_int),
                ("sleep_time"       , c_int)]

#Ctype structure for thread_identifier_info_data_t
class ThreadIdentInfo(Structure):
    _fields_ = [("thread_id"        , c_ulonglong),
                ("thread_handle"    , c_ulonglong),
                ("dispatch_qaddr"   , c_ulonglong)]

class ProcThreadInfo(Structure):
    _fields_ = [("pth_user_time"    , c_ulonglong),
                ("pth_system_time"  , c_ulonglong),
                ("pth_cpu_usage"    , c_int),
                ("pth_policy"       , c_int),
                ("pth_run_state"    , c_int),
                ("pth_flags"        , c_int),
                ("pth_sleep_time"   , c_int),
                ("pth_curpri"       , c_int),
                ("pth_priority"     , c_int),
                ("pth_maxpriority"  , c_int),
                ("pth_name"         , c_char_p)]

"""
Enum and defines
"""

# breakpoint flags
ONE_TIME    = 0
PERSISTENT  = 1

TEXT  = 0
DATA  = 1

# kernel events
NOTE_FORK     = 0x40000000
NOTE_EXEC     = 0x20000000
NOTE_SIGNAL   = 0x08000000
NOTE_EXIT     = 0x80000000

# exception types
EXC_BAD_ACCESS       = 1  # Could not access memory
EXC_BAD_INSTRUCTION  = 2  # Instruction failed
EXC_ARITHMETIC       = 3  # Arithmetic exception
EXC_EMULATION        = 4  # Emulation instruction
EXC_SOFTWARE         = 5  # Software generated exception
EXC_BREAKPOINT       = 6  # Trace breakpoint etc.
EXC_SYSCALL          = 7  # System calls.
EXC_MACH_SYSCALL     = 8  # Mach system calls.
EXC_RPC_ALERT        = 9  # RPC alert
EXC_CRASH            = 10 # Abnormal process exit
EXC_RESOURCE         = 11 # Hit resource consumption limit
EXC_GUARD            = 12 # Violated guarded resource protections
EXC_CORPSE_NOTIFY    = 13 # Abnormal process exited to corpse state


VM_PROT_NONE          = 0x00
VM_PROT_READ          = 0x01 # read permission
VM_PROT_WRITE         = 0x02 # write permission
VM_PROT_EXECUTE       = 0x04 # execute permission
VM_PROT_NO_CHANGE     = 0x08
VM_PROT_COPY          = 0x10
VM_PROT_WANTS_COPY    = 0x10
VM_PROT_IS_MASK       = 0x40

VM_FLAGS_ANYWHERE     = 0x01

# Mapping ctypes to python types
SEARCH_TYPES = {c_char      : 'c',
                c_byte      : 'b',
                c_ubyte     : 'B',
                c_short     : 'h',
                c_ushort    : 'H',
                c_int       : 'i',
                c_uint      : 'I',
                c_long      : 'l',
                c_ulong     : 'L',
                c_longlong  : 'q',
                c_ulonglong : 'Q',
                c_float     : 'f',
                c_double    : 'd'}


