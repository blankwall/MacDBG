### Table of contents
  
[TOC]  
  
##TODO:  
  
Priority:  
  
- fix dyld map   
- finish thread porting in python  
- fix symbol resolution read in size  
- change test to examples finish python tests  
- function and variable renaming -> Follow standard convention as discussed  
- write thread tests in python  
- Write example scripts  
- More examples python C better directory structure for more examples  
- More formal testing needed  
   

**Long Term:**  
- - Watchpoints - Hardware and Software  
- Floating point support  
- GUI support (curses) like in lldb  
- Remove TODO from readme to its own doc  
- Remove authors from readme to its own doc  
- Remove notes  
- Remove test and auto_test  
**Recently Done**  
- ~~change globals to structs~~  
- ~~continue_ --> Still needed in python  ~~  
- ~~Add a run function to run program from the command line ~~  
- ~~mach_vm_read_overwrite ~~  
- ~~list all threads~~  
    - ~~list current thread position, number of threads~~  
    - ~~Basics done still need more~~  
- ~~return on error~~  
- ~~loaded libraries~~  
- ~~single-step -- No longer needed~~  
- ~~Rewrite memory_map (integrate into Python)~~  
- ~~Search functionality~~  
- ~~Integrate lazy exception server starting~~  
  
#Mac Debugger
---
Mac Debugger was created with the focus on giving the programmer a powerful framework to programatically create scripts to debug programs on Mac OSX not found in the lackluster selection for the platform.

The core of macdbg, written in C, is kept as minimal as possible to provide enough basic interaction between the kernel and userland to create powerful features. Higher level functionality is left to the Python implementation such as stack tracing, dissasembly, watchpoints, thread state, and more. A wrapper class is provided for the programmer to create a scripting program along with a python interactive mode to mimic lldb and gdb.  

## Getting Started
---
```sh
$ git clone https://tbohan@bitbucket.org/tbohan/mac_debugger.git
```
  
Navigate to the mac_debugger directory, then `cd macdbg` and `make`. The shared library libmcdb.dylib will be compiled and several binaries.
  
## Plugins  
---
- Captsone -- optional
  
## Usage  
---
#### Running a test debugger on a test program.
1. `cd test` and open another terminal.
2. Run `./test_prog`
3. This is just a test rogram which we will be attach and set breakpoints on. Hit `f`. To end it, press `c` to crash it. 
4. Run it once more without pressing anything afterwardsp
5. Copy the pid  
6. On a seperate terminal, run `sudo ./debugger [pid]`
7. This is an example program (source is macdbg_test.c) where the breakpoints are hardcoded after the fork and crash.  
8. Paste your pid into [pid] without the bracket and hit `enter`
10. It should display **Thread created succesfully.**  
11. In the test_prog terminal, hit `f` and press `enter`. Notice how 1 2 3 doesn't print, that's because we put a breakpoint there!
12. Back to the debugger terminal, hit `enter` three times or until you see **breakpoint 1 is added**. This is how we're registering breakpoints!
13. Back to macdbg_test terminal, you should see the normal two lines of 1 2 3 printed. We've continued on from breakpoint. 
14. Type in `c` to crash, this should be the second breakpoint.
15. Back to debugger terminal, hit `enter` and **OMG A CRASH** should show, and hit `enter`. This continues our program again and both programs should be terminated. 

## References  
---
* [vdb] - Philosophical debugger reference
* [readmem] - Command line tool to read memory  
* [m3u] - Disabling m3u in iTunes
* [cmu] - mach exception handling paper
* [vm_read] - test code of vm_allocate, vm_read, and vm_deallocate
* [exception_handlers] - blog post on understanding mach-o exception handlers
* [exception] - stackoverflow to register mach_port for exception handling in 64-bit
* [base_address] - Getting base address in Mac

## Authors  

|                   |                         | 
 ------------------ | -------------------------
| Tyler Bohan 		| tbohan@silversky.com       
| Gayathri Thiru	| gthiru@silversky.com 
| Kenny Yee         | kyee@silversky.com


   [vdb]: https://github.com/vivisect/vivisect
   [m3u]: https://github.com/gdbinit/Disable-m3u/blob/master/hack.cpp
   [cmu]: http://www.cs.cmu.edu/afs/cs/project/mach/public/doc/unpublished/exception.ps
   [vm_read]: http://www.cs.cmu.edu/afs/cs/project/mach/public/doc/unpublished/examples/vm_read.c
   [exception_handlers]: https://www.mikeash.com/pyblog/friday-qa-2013-01-11-mach-exception-handlers.html
   [exception]: http://stackoverflow.com/questions/2824105/handling-mach-exceptions-in-64bit-os-x-application
   [base_address]: http://www.ownedcore.com/forums/world-of-warcraft/world-of-warcraft-bots-programs/wow-memory-editing/463184-os-x-base-address-of-process.html
   [readmem]: https://github.com/gdbinit/readmem/blob/master/readmem/main.c