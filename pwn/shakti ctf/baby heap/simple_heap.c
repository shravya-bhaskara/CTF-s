#include<stdio.h>
#include<time.h>
#include<string.h>
#include<stdlib.h>

unsigned int target = 0xdeadbeef;

int get_inp(char * buffer, int len) {
    int retval = read(0, buffer, len);
    if ( retval == -1)
        exit(0);
    char *ptr = strchr(buffer, 10);
    if (ptr != NULL)
        *ptr = '\0';
    return 0;
}

int getint(int len) {
    char buffer[len];
    get_inp(buffer, len);
    return atoi(buffer);
}

char * m_array[0x4];

int main(){
// initialize();


puts("\n=================");
puts(" | Baby Heap | ");
puts("=================\n");

printf("Here's a generous leak for you! %p\n\n", &puts);

int ch;

int idx = 0;
int max_elements = 4;

int *m;
m = (int*)malloc(0x88);
printf("Here's one more generous leak for you: %p\n", m-0x10);
free(m);

while(1){

printf("\nMENU\n\n1. malloc %u/%u\n", idx, max_elements);
printf("2. edit\n3. target\n4. quit\n> ");
fflush(stdout);
ch = getint(2);

switch(ch){

case 1:
	fflush(stdout);
	if(idx < 0){
		puts("No negative indices allowed!");
		exit(0);
	}
	else if(idx > max_elements){
		puts("maximum requests reached!");
		exit(0);
	}
	else{
		puts("Enter size: ");
		int size = getint(32);
		m_array[idx] = malloc(size);
		if(m_array[idx]){
			puts("data: ");
			get_inp(m_array[idx], size);
			idx++;
		}
		else{
			puts("request failed!\n");
			exit(0);
		}
	}
	break;
case 2:
	puts("Enter index: ");
	int i = getint(8);
	if(m_array[i]){
		puts("Enter size: ");
		int s = getint(32);
		puts("data: ");
		get_inp(m_array[i], s);
	}else{
		puts("Index not allocated!");
		exit(0);
	}
	break;

case 3:
	printf("\ntarget: %d\n", target);
	break;
case 4:
	puts("Ok Bye!");
	exit(1);
default:
	puts("Invalid Option! ");
}
}

return 0;
}
	
	
