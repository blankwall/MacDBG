## DIRECTORIES ##
PYTHON_DIR = ../python

## DEPENDENCIES ##
OBJ1 = macdbg_test.o
OBJ2 = test_prog.o

## BINARIES ##
BIN1 = debugger.app
BIN2 = test_prog.app

LIB = libmcdb.dylib

## COMPILER
CC = clang
CFLAGS = -std=gnu99 -Wall

all: $(BIN1) $(BIN2)

# debugger binary using macdbg_test.c
$(BIN1): $(OBJ1)
	$(CC) $(CFLAGS) $^ -o $@ $(LIB)

# test_prog binary using test_prog.c
$(BIN2): $(OBJ2)
	$(CC) $(CFLAGS) $^ -o $@
	@-cp $@ $(PYTHON_DIR)

$(OBJ1): ../mcdb.h

$(OBJ2): test_prog.c
	$(CC) -c $^

.PHONY : clean cleanobj cleanbin

clean: cleanobj cleanbin

cleanobj:
	rm *.o

cleanbin:
	rm $(BIN1) $(BIN2) $(PYTHON_DIR)/$(BIN2)