#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>
#include<unistd.h>
#include <sys/mman.h>

#define SHELLCODE_LEN 1024

// gcc pack_alpha.c -fno-stack-protector -z execstack -o pack_alpha

int j = 0;
unsigned int name_size;


void initialize()
{
	setvbuf(stdin,0,2,0);
	setvbuf(stdout,0,2,0);
	setvbuf(stderr,0,2,0);
	alarm(60);
}


int main(){

initialize();
char email[10];
char age[3];
unsigned int length;
char name[96];

puts("Welcome to our wolf camp!\n");

printf("Please provide us with your personal information and we shall allocate you to your rooms.\n");
printf("Email address: ");
fgets(email, 10, stdin);
printf("Age: ");
fgets(age, 3, stdin);
getchar();
printf("Your room number is: %p\n", &name);
printf("Length of your name: ");
scanf("%u", &length);
getchar();
if((int)length>0x60){
	printf("\nWhoa! Such a huge name??\n\n");
	exit(0);
}else{
	printf("Enter your name: ");
	name_size = read(0, &name, length);// length = -1 = 0xffffffff
	//getchar();
	fflush(stdin); 
	while(j<(int)name_size - 8){
		if(!(((name[j]-0x30)>=0 && (name[j]-0x30)<=9) || isalpha(name[j]) !=0 || name[j]=='\x00')){
			printf("\nBad character!\n");
			exit(0);
		}
		j++;
	}
	printf("\nGreat you may move to your rooms and await further instructions.\n\n");
	return 0;
	printf("Invalid name! Try again perhaps.\n\n");
	}


}

