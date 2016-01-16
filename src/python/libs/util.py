from inspect import stack

def err_noattach(func):
    '''decorator to check if instance of macdbg is attached'''
    def wrapper(*args, **kwargs):
        if (args[0].task == None):  # args[0] is self
            fname = func.func_name
            ERR("No process attached: {0}".format(fname))
            return 0
        return func(*args, **kwargs)
    return wrapper

def LOG(msg):
    '''Prints log message in the format [*function_name] LOG: msg'''
    return "\n[*{0}] LOG: {1}".format(stack()[1][3], msg)

def ERR(msg):
    '''Prints error message in the format [-function_name] ERR: msg'''
    print "\n[-{0}] ERR: {1}".format(stack()[1][3], msg)

def err_cont():
    '''Prompts user to continue or exit the program'''
    cont = ""
    while cont != 'n' or cont != 'y':
        cont = raw_input("\nContinue? [Y/n]: ")
        cont = cont.lower()
        if cont == 'n':
            exit(1)
        elif cont == 'y':
            break

