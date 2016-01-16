/*
 *  Test file to debug. Using sudo ./debugger and attach to pid. 
 *  Breakpoint is added after user inputs f or c
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

char* blue = "blue";
char k[5] = {'a', 'a', 'a', 'f','c'};

int abc(int x, int y, int z){
    printf("%d %d %d\n", x,y,z);
    return 0;
}

int main() {
    char c;
    int pid;
    int l = 1;
    c = *blue;
    printf("My process ID : %d\n", getpid());
    printf("ADDRESS OF ABC: %p\n", abc);
    printf("ENTER f for fork c for crash or anything else to continue\n");
    while(1) {
        if(l > 6){
            exit(-10);
        }
        sleep(2);
        // c = k[l++];
        if(l == 4){
            c = 'f';
        } else if (l == 5){
            c = 'c';
        } else {
            c = ' ';
        }
        l++;

        if(c == 'f') {
            printf("FORK\n");
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
