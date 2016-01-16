from parse.macho import *
from parse.BinaryData import *
import subprocess

def demangle(names):
    args = ['c++filt']
    args.extend(names)
    pipe = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, _ = pipe.communicate()
    demangled = stdout.split("\n")

    # Each line ends with a newline, so the final entry of the split output
    # will always be ''.
    assert len(demangled) == len(names)+1
    return demangled[:-1]

a = open("a.out").read()
# print len(a)
b = BinaryData(a)
c = MachOFile(b)

for i in c.symbols_by_name:
	print demangle([i]) , i