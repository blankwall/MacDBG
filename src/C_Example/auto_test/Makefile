## Dependencies ##
OBJ1 = auto_test_prog.o
OBJ2 = automated_test.o

## Binaries ##
BIN1 = auto_test.app
BIN2 = auto_debug.app

LIB = libmcdb.dylib

## Compiler ##
CC = clang
CFLAGS = -std=gnu99 -Wall

all: $(BIN1) $(BIN2) 

# auto_test binary using auto_test_prog.c
$(BIN1): $(OBJ1)
	$(CC) $(CFLAGS) $^ -o $@

# auto_debug binary using automated_test.c
$(BIN2): $(OBJ2)
	$(CC) $(CFLAGS) $^ -o $@ $(LIB)

$(OBJ1): auto_test_prog.c
	$(CC) $(CFLAGS) -c $^

$(OBJ2): ../../mcdb.h ../../memory.h

.PHONY : clean cleanobj cleanbin

clean: cleanobj cleanbin

cleanobj:
	rm *.o

cleanbin:
	rm $(BIN1) $(BIN2)