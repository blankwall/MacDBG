## Directories ##
MACH_DIR = .mach_gen
TEST_DIR = C_Example
AUTO_DIR = $(TEST_DIR)/auto_test
PYTHON_DIR = python
PYTHON_DIR_EX = python/examples

## libmcdb Dependencies ##
MACH_OBJS = $(MACH_DIR)/mach_excServer.o $(MACH_DIR)/mach_excUser.o
OBJECTS = debug_main.o util.o breakpoint.o exception.o memory.o thread.o dyldcache_parser.o $(MACH_OBJS)

## Binary ##
LIB = libmcdb.dylib

## Compiler ##
CC = clang

## FLAGS ##
CFLAGS = -std=gnu99 -Wall -fvisibility=hidden -Qunused-arguments -current_version 1.0 -compatibility_version 1.0 

all: $(TEST_DIR)/$(LIB) tst auto_test

debug: CFLAGS += -DDEBUG -g
debug: all

no_o: all cleanobj_all

$(TEST_DIR)/$(LIB): $(OBJECTS)
		$(CC) $(CFLAGS) -dynamiclib $^ -o $(LIB)
		cp $(LIB) $(PYTHON_DIR)
		cp $(LIB) $(PYTHON_DIR_EX)
		mv $(LIB) $(TEST_DIR)
		cp $@ $(AUTO_DIR)

# test directory make
tst:
	@-$(MAKE) -C $(TEST_DIR)

# test/auto_test directory make
auto_test:
	@-$(MAKE) -C $(AUTO_DIR)

## DEPENDENCIES ##
debug_main.o: debug_main.h thread.h

util.o: mcdb.h

breakpoint.o: breakpoint.h memory.h

exception.o: exception.h

memory.o: memory.h

thread.o: thread.h

dyldcache_parser.o: dyldcache_parser.h

mach_excUser.o: $(MACH_DIR)/mach_exc.h 

mach_excServer.o: $(MACH_DIR)/mach_excServer.c
	$(CC) -c $^

.PHONY : clean  cleanobj_all cleanbin cleanobj cleanpyc

# remove  all .o and binaries recursively by calling all make clean's
clean: cleanobj_all cleanbin

# remove all .o but keep binaries
cleanobj_all: cleanobj
	@-$(MAKE) -C $(TEST_DIR) cleanobj
	@-$(MAKE) -C $(AUTO_DIR) cleanobj

# remove all .o made from this makefile
cleanobj:
	rm *.o $(MACH_DIR)/*.o

# remove all binaries
cleanbin:
	rm $(TEST_DIR)/$(LIB) $(AUTO_DIR)/$(LIB) $(PYTHON_DIR)/$(LIB)
	@-$(MAKE) -C $(TEST_DIR) cleanbin
	@-$(MAKE) -C $(AUTO_DIR) cleanbin

# remove all pyc files (nothing depends on this)
cleanpyc:
	rm $(PYTHON_DIR)/libs/*.pyc $(PYTHON_DIR)/libs/parse/*.pyc
