# fd

## Problem:

Mommy! what is a file descriptor in Linux?

* try to play the wargame your self but if you are ABSOLUTE beginner, follow this tutorial link:
https://youtu.be/971eZhMHQQw

ssh fd@pwnable.kr -p2222 (pw:guest)

## Solution:
Connect with "ssh fd@pwnable.kr -p2222" and enter the password as "guest". 
Type in ls, to know what files are present.
-There are three files present: flag, fd, fd.c
With the help of command "cat fd.c" let's know what program is actually running.

## source code :

```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
	if(argc<2){
		printf("pass argv[1] a number\n");
		return 0;
	}
	int fd = atoi( argv[1] ) - 0x1234;
	int len = 0;
	len = read(fd, buf, 32);
	if(!strcmp("LETMEWIN\n", buf)){
		printf("good job :)\n");
		system("/bin/cat flag");
		exit(0);
	}
	printf("learn about Linux file IO\n");
	return 0;

}
```

If we take a look at fd.c (code is given above), we can see that program is asking for minimum 2 arguments. 
arg[0] is "./fd"
arg[1] is a character
arg[2] is a character.

We can also see that fd = atoi(arg[1] ) - 0x1234. This means whatever input we give as arg[1], will be converted to a numeric and 0x1234 is subtracted from it.
Also fd is used in the read statement, i.e 
len = read(fd, buff, 32)
In order to initialize fd to 0, arg[1] must be equal to 0x1234 or arg[1] = 4660
In the next line, the program runs an if statement and compares our buffer with string "LETMEWIN\n". And so we know that we need to enter string "LETMEIN" so that the flag gets printed.

## Flag: 
```mommy! I think I know what a file descriptor is!!```

