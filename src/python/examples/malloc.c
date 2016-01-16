#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

void* x(int y){
	return malloc(y);
}

int main(){
	for(int i = 0; i < 10; i++){
		sleep(2);
		x(5);
	}
	printf("DONE\n");
}