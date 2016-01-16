//Pass in the program to run attach saf.py and press enter to bypass sip

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

pid_t spawn_process(char *command, char *args[]) {
    execv(command, args);   // run the command
}

int main(int argc, char** argv){
    pid_t pid;
    char *my_args[2];
    my_args[0] = argv[1];
    my_args[1] = NULL;

    printf("My process ID : %d\n Hit enter to spawn process\n", getpid());
    getchar();
    pid = spawn_process(argv[1], my_args);
    printf("%d\n", pid);
}