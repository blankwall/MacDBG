Mac Debugger
---
Mac Debugger was created with the focus on giving the programmer a powerful framework to programatically create scripts to debug programs on Mac OSX not found in other products for the platform.

The core of macdbg, written in C, is kept as minimal as possible to provide enough basic interaction between the kernel and userland to create powerful features. Higher level functionality is left to the Python implementation such as stack tracing, dissasembly, watchpoints, thread state, and more. A wrapper class is provided for the programmer to create a scripting program.  

NOTE: This is an Alpha implementation more showing concepts and ideas but not fully refined. Expect the Beta version in the coming months with more refined variable naming cleaner code and more useable examples. Thanks for all the interest suggestions comments and help welcome!

## Getting Started
---
```sh
$ git clone https://github.com/blankwall/MacDBG.git
```
  
Navigate to the MacDBG directory, then `cd src` and `make`. The shared library libmcdb.dylib will be compiled and several binaries.
  
## Plugins  
---
- Captsone -- optional
  
## Usage  
---
#### Running a test debugger on a test program.
1. `cd Python/examples` and open another terminal.
2. Run `sudo ./basic_example.py`
3. This is just a test rogram which we will be attach and set breakpoints on. Hit `f` to fork the program enter to continue or press `c` to crash it. You should see breakpoint output like seen below.
4. There are many other examples in the examples directory most having at least a small description available, nore descriptions and usage coming soon.
5. Most examples will spawn a program but nearly all of them can take a PID and attach to that. Please note some were written specifaclly for a specific program such as malloc.py was written to track mallocs on Firefox changes would need to be made to make it work on other programs.
