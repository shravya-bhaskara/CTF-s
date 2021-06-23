# Super-Safe-Integers 

* This challenge is one of integers overflows type. 
 
 Challenge Description : ```Overflows are only for strings, right?```

* Given source code : 
```
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

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
    system("/bin/sh");
}
 
int main()
{
    init();
    srand(time(0));
    int a = rand();
    int input;
    printf("Can you overflow me? The target number is %d\n",a);
    scanf("%d", &input);
    if(input < 0)
    {
        puts("Nice try! If it was that easy even I could have cracked it!");
        exit(0);
    }
    int value = a + input;
    if(value < a)
    {
        puts("Wow, you beat me, here's your shell!");
        win();
    }
    else
    {
        puts("Well, that didn't work. Try again!");
    }
    return 0;
}
```
# Solution : 
* In the above code, we can see that it asks for an integer input, adds our input to variable 'a' which contains a random value returned by the program, and this value is then compared and checked if it's less than 0. 
* Also, we cannot enter a negative integer as our input.
* So our only option is to overflow the buffer in a way that it returns a number less than 0.
* We know that an integer occupies 4 bytes of space in the memory and any number that occupies mmore than 4 bytes of space is considered as an overflow and the extra bit will be ignored. Also since 'value' is an integer, the given range of integers to avoid overflow is (-2147483648 - 0 - 2147483647) 
* Since we can't give negative integers as input, we need to choose a number which will overflow value = a + input.
* One solution maybe to choose any number greater than 2147483647. But the more accurate answer would be if we knew the minimum number needed to cause the overflow.
* Once we run the program, we can see that the target number is different on each run. That is because a random number is returned each time we run the program. However to find the minimum number required for overflow, we can easily subtract the target number from 2147483647.
* thus number required = 2147483647 - target_number + 1

# Python code : 

```
from pwn import *
p = process("./Safe-Integers.chall")

st = p.recv()
num = int(st[42:])
p.send(str(2147483647 - num + 1))

p.interactive()
```
