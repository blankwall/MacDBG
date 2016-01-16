# C-Style Guide
This style guide is meant for team development between **Tyler**, **Gayathri**, and **Kenny** on the ***Mac Debugger***. In no way is this guide meant to be universal or extremely strict. Listed are only the most important styles used most frequently when coding that will define the overall structure. **Anything left out, intentionally or not, is left to the coder's best judgements.** Any additions or changes should be discussed with the team via [bae-slack]. 
  
**Work in progress*  
  
### Top Core Philosophies:  
1. Maintainability  
2. Consistency  
3. Readability  
4. Code Density  
  
With maintainability taking priority to all coding styles preceding it.  
### Coding 101:  
All functions should be readable and obvious. When a function gets too complicated, use seperate functions to augment that.  
  
## Style:  
### Naming Conventions:  
When in doubt: lower-case seperated by underscores. Such as:  
```sh
int this_is_a_variable;
```
  
To name a few, this should adhere to  
- local variables  
- function names  
- file names  
  
Exceptions:  
- defines should all be UPPERCASE, seperated by _ underscores.  
- globals  
```sh
#define MAX_BREAKS 100
```  
  
### Variables:  
- All declarations should be defined at the top of the function, then assigned when most appropriate. Besides knowing what variables are being used, the reader will know the types the function uses (mach_port_t, threads, etc.)  
  
```sh
vm_address_t get_base_address(mach_port_t task) {
    kern_return_t kret;
    vm_region_basic_info_data_t info;
    vm_size_t size;
    mach_port_t object_name;
    ...
    
    mach_vm_address_t address = 1;

    count = VM_REGION_BASIC_INFO_COUNT_64;
    
    ...
```
- Pointer declarations (*) in variables or as arguments should be next to the variable name and not the type. Unless you're defining a function.  
```sh
void* kqueue_loop(void *kp) {
    x86_thread_state64_t *break_state;
    ...
```
  
### To    space or not to space  
To space:  
- Between closing brace ( and { open bracket.  
- Between arithmetic or conditionals  
- Before an after an assignemnt =  
```sh
if(patch_addr <= MAX_BREAKS + 1) {
  int size = 10;
```  
  
not to:  
- Between a function call or decleration and parenthasis. printf( .. ) and not printf (...);  
- Inside of parenthesis. if( a < b ) should be if(a < b)  
### Brackets:  
- Are inline to the function or conditional, with a space between closing ) and open {. Closing bracket } should be on its seperator line, tab-aligned with the function its closing. The exception is for else if and else statements, which are defined in line with the closing brace.  
```sh
int add_breakpoint(mach_port_t task) {
   if(patch_addr <= MAX_BREAKS) {
       DEBUG_PRINT("[-add_breakpoint] INVALID BREAKPOINT ADDRESS %lx\n", patch_addr);
        return -1;
    } else if(current_break >= MAX_BREAKS) {
       DEBUG_PRINT("[-add_breakpoint] Max %d breaks reached!\n", MAX_BREAKS);
        return -1;
    }
}
```
[bae-slack]: <https://bae-labs.slack.com/messages/macdebug/>