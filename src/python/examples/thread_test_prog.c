/*
 *  Test file to debug. Using sudo ./debugger and attach to pid. 
 *  Breakpoint is added after user inputs f or c
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char* blue = "blue";

int abc(int x, int y, int z) {
    printf("%d %d %d\n", x,y,z);
    return 0;
}

int cde() {
    while(1){
        sleep(10);
        printf("HELLO\n");
    }
    return 0;
}

int main() {
    int tid;
    int err = pthread_create(&tid, NULL, (void *(*)(void*))cde, 0);
    if (err != 0)
        printf("\n[-start] can't create thread :[%s]", strerror(err));
    else
        printf("\n[-start] Thread created successfully %d\n", 0);

    char c;
    int pid;
    c = *blue;
    printf("My process ID : %d\n", getpid());
    printf("ADDRESS OF ABC: %p\n", abc);
    printf("ENTER f for fork c for crash or anything else to continue\n");
    while(1) {
        c = getchar();

        if(c == 'f') {
            pid = fork();
            if(pid == 0) {
                exit(-1);
            }
        }

        if (c == 'c') {
            blue = 0;
            *blue = 99;
        }

        printf("%c\n", c );
        abc(1,2,3);
    }
}
