#include "mcdb.h"

EXPORT
void* safe_malloc(size_t x) {
    void *mal = malloc(x);
    if(mal == NULL) {
        fprintf(stderr, "[-safe_malloc] Error Exiting\n");
        exit(-1);
    }
    
    memset(mal, 0, x);
    return mal;
}

void* safe_realloc(void* ptr, size_t x) {
    void *mal = realloc(ptr, x);
    if(mal == NULL) {
        fprintf(stderr, "[-safe_malloc] Error Exiting\n");
        exit(-1);
    }
    return mal;
}

EXPORT
void print_byte(char *byte) {
    int i, len;
    len = strlen(byte);

    for(i = 0; i < len; ++i) {
        printf("%x ", byte[i] & 0xff);
    }

    puts("");
}

EXPORT
void print_bytes(char *byte, int len) {
    int i;

    for(i = 0; i < len; ++i) {
        printf("%x ", byte[i]&0xff);
    }

    puts("");
}

EXPORT
char* exception_to_string(exception_type_t exc) {
    switch(exc) {
        case EXC_BREAKPOINT     : return "EXC_BREAKPOINT";
        case EXC_BAD_ACCESS     : return "EXC_BAD_ACCESS";
        case EXC_BAD_INSTRUCTION: return "EXC_BAD_INSTRUCTION";
        case EXC_ARITHMETIC     : return "EXC_ARITHMETIC";
        case EXC_EMULATION      : return "EXC_EMULATION";
        case EXC_SOFTWARE       : return "EXC_SOFTWARE";
        case EXC_SYSCALL        : return "EXC_SYSCALL";
        case EXC_MACH_SYSCALL   : return "EXC_MACH_SYSCALL";
        case EXC_RPC_ALERT      : return "EXC_RPC_ALERT";
        case EXC_CRASH          : return "EXC_CRASH";
        case EXC_RESOURCE       : return "EXC_RESOURCE";
        case EXC_GUARD          : return "EXC_GUARD";
        case NOTE_EXEC          : return "EXEC";
        case NOTE_FORK          : return "FORK";
        case NOTE_SIGNAL        : return "SIGNAL";
        case NOTE_EXIT          : return "EXIT";

        default:
            return "[-exception_to_string] unknown exception type!";
    }
}


