#include<stdio.h>

void win(){
	system("sh");
}

int main(){
	char inpBuf[20];
	read(inpBuf, 20, stdin);
	printf(inpBuf);
	exit(0);
}
