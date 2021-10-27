# Sample Program:
Consider the following c program:
```c=
// gcc chall.c -fno-stack-protector -no-pie -o chall

#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int main(){
int auth = 0;
char passphrase[20];
printf("Enter the passphrase: ");
gets(passphrase);
if(auth){
    printf("Access granted!\n");
}else{
    printf("Access denied!\n");
}
return 0;
}
```
Before we junp into exploitation, we need to understand the above c program at the very basic level. I shall take you through each line of code in the sample program, before directly identifying and exploiting the vulnerability.

### Code analysis:
As we see, in the above source code, we have a main() function, in which most of the action that the program needs to perform, is described.
- We see that a variable of type `int` has been declared and initialized to `0`
- There is a character array `passphrase` of size 20 bytes declared.
- `gets(passphrase)` is used to read data from our input.
- The next `if - else` condition checks if the variable `auth` is `true` or `false`. If `true`, the `if` condition is satisfied and `Access granted!` is printed out. If `false`, we know that `Access denied` will be printed out.
- However, since auth is declared as an integer and not a boolean, how do we determine if it is `true` or `false`?
        - To do that, we must understand that in programming, only the integer `0` is evaluated as `false` whereas any other non-zero value is evaluated as `true`. For example:
            - if `auth = -1` --> evaluated as`true`
            - if `auth = 0` --> evaluated as `false`
            - if `auth = 1` --> evaluated as `true` and so on. 
        - So any non-zero integer will be considered as a `true` case and only a zero integer will be considered as a `false` case.
- In the above program, we observe that the variable `auth` is initialized to 0, which means that by default, it will not pass the `if` statement check and will simply print `Access denied`. 
```
Enter the passphrase: 1234abcd
Access denied!
```
- However, our goal is to somehow manipulate the program and grant ourselves the access we need. In order to do that, the variable `auth` must contain any non-zero value so as to satisfy the `if` statement condition. How do we do that?

### Finding the vulnerability and exploiting it:
As discussed above, the obvious vulnerability here is gets(). `gets()` takes no limit on the number of characters to be read. It will continue to read until it encounters an EOF or a terminating newline character. This gives the users a flexibility to enter as many characters as possible without posing any kind of checks on the size of our input string. How is this beneficial to our cause?
Since there is no limit to the number of characters entered let's consider a scenario. Before that, we must keep in mind that both our variables `auth` and `passphrase` though of different types, will always be stored at some location in the memory at the time of their declaration. Therefore, we can be positive about the fact that we can find our both input buffer stored in the variabe `passphrase` and also the initialized variable `auth` at some locations on the stack. Take a look at the image below:

![stack_structure](https://i.imgur.com/o2lr3Lx.png)

The above diagram showcases how variables are present in the memory. **Please note that all the addresses mentioned in the above diagram are purely taken for explanation purpose. These addresses will differ while running the program. However the concept remains the same.**
So what inferences do we draw?
- Stack grows from a higher memory address to a lower memory address. 
- The return instruction pointer is present 8 bytes above the base pointer. 
- At some location below the base pointer, both the variables `int auth` as well as the character array `passphrase` are located. 
**What is important to note is that, since our input is stored in variable `passphrase` present at the location `0x4000`, it is also possible that at some point, as we keep writing more and more data, we may happen to overwrite the location `0x4030` where the variable `auth` is stored in memory. Since gets() allows us to enter as many characters as possible, we shall make use of this vulnerability to overwrite `auth` (i.e ovewrite the location `0x4030`) in such a way that it no longer contains `0x00000000`.**

Our goal is to make use of this vulnerability and grant ourselves the access we need. 
Let us go through the exploitation of this piece of code, step by step. 
- Firstly, we must notice that in order to gain access, the variable `auth` which is initialized to 0, must to be changed to anything else but 0 in order to satisfy the `if` condition.
- To change the value in the variable `auth`, we need to locate its position and offset in memmory. Provide a likey offset only to change the variable value and be careful not to overfow `rip`, lest it should result in segfaults.
- Finding the offset of the variable `auth` from where our input is read into the buffer. To do this, I will make use of gdb to demonstrate the how the memory would look like.
    
### Step 1:
Analysis:
- Use the file command to check if its a 64-bit or a 32-bit, statically or dynamically linked binary.
`chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=08f246fdc9fa6304b5daf8be4175413a05a80f31, for GNU/Linux 3.2.0, not stripped
`
The binary is 64-bit dynamically linked. What does this mean?
Firstly, a 64-bit binary implies that each location in memory would be 8 bytes long. Also all the registers used would be 64 bit
- Dive into gdb! If you do not have gdb installed, you may follow the following steps, else you may skip to the debugging part with gdb!
- For installation:
```
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
echo "DONE! debug your program with gdb and enjoy"
```
- **In case you aren't aware of the use of gdb, let me tell you that gdb is a debugger for C and C++. It allows us to do things like run the program up to a certain point then stop and print out the values of certain variables at that point, or step through the program one line at a time and print out the values of each variable after executing each line. Basically helping us debug through the program line by line.**

- Before starting off with debugging in gdb, it is our choice to check for the protections available in the binary. For example, check if `canary`, `NX` and `PIE` are enabled or disabled. What are these protections? What is their significance?
- `canary` is like a layer of protection added in order to prevent overflowing of the stack. If `canary` is disabled, it means that one has the liberty to overflow the stack and cause the program to redirect its execution. Usually `canary` is present at some location below the base pointer on the stack frame and contains a random value so that whenever an overflow occurs, it is detected by the program. Consider the below image for the basic understanding of the canary.

![canary](https://i.imgur.com/6FJNsfn.png)
As we can see in the above image, canary is set at location `0x4038` on the stack and contains some random value that is initilized when the program is run. This canary value is always different on different runs of the program, however it does serve as a protection against an overflow attack. How? Whenever a user wishes to overwrite the return pointer to redirect the execution, he must write past `canary`. As a result, when the canary check fails, stack smashing is detected.

- `NX` is a protection given to disable the user from using shellcodes to directly the users to spwan a shell. This kind of protection and its uses and applications will be discussed at some other time.
- `PIE` is yet another protection scheme wherein the addresses are set only at run time. This kind of protection too will be discussed later. For now all we need to know is about `canary`.

A checksec on the above binary file shows:
```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
gdb-peda$ 
```
We see that `canary` and `PIE` are diabled whereas `NX` is enabled. However, we need only be concerned about the `canary` at this point, and seeing how it is disabled, we need not worry about any canary checks or stack smashing errors. We have all the freedom to overwrite any part of the memory as we want.

    
### Step 2:
Disassemble the main() function:

```
Dump of assembler code for function main:
   0x0000000000401176 <+0>:	endbr64 
   0x000000000040117a <+4>:	push   rbp
   0x000000000040117b <+5>:	mov    rbp,rsp
   0x000000000040117e <+8>:	sub    rsp,0x20
   0x0000000000401182 <+12>:	mov    DWORD PTR [rbp-0x4],0x0
   0x0000000000401189 <+19>:	lea    rdi,[rip+0xe74]        # 0x402004
   0x0000000000401190 <+26>:	mov    eax,0x0
   0x0000000000401195 <+31>:	call   0x401070 <printf@plt>
   0x000000000040119a <+36>:	lea    rax,[rbp-0x20]
   0x000000000040119e <+40>:	mov    rdi,rax
   0x00000000004011a1 <+43>:	mov    eax,0x0
   0x00000000004011a6 <+48>:	call   0x401080 <gets@plt>
   0x00000000004011ab <+53>:	cmp    DWORD PTR [rbp-0x4],0x0
   0x00000000004011af <+57>:	je     0x4011bf <main+73>
   0x00000000004011b1 <+59>:	lea    rdi,[rip+0xe63]        # 0x40201b
   0x00000000004011b8 <+66>:	call   0x401060 <puts@plt>
   0x00000000004011bd <+71>:	jmp    0x4011cb <main+85>
   0x00000000004011bf <+73>:	lea    rdi,[rip+0xe65]        # 0x40202b
   0x00000000004011c6 <+80>:	call   0x401060 <puts@plt>
   0x00000000004011cb <+85>:	mov    eax,0x0
   0x00000000004011d0 <+90>:	leave  
   0x00000000004011d1 <+91>:	ret    
End of assembler dump.
```

- In the above disassembly of the main() function, we see that the stack size established in the prologue, ie
```
   0x0000000000401176 <+0>:	    endbr64 
   0x000000000040117a <+4>:	    push   rbp
   0x000000000040117b <+5>:	    mov    rbp,rsp
   0x000000000040117e <+8>:	    sub    rsp,0x20
```
is 0x20 bytes. The prologue of any function in assembly, is basically the part of the program that establishes the stack frame. In this case, `mov rbp, rsp` and `sub rsp, 0x20` are the lines of code used to establish a stack frame of size 0x20 bytes.
- To proceed further, we must understand that every variable declared in C, in fact is stored in some location on the stack. Arguments to the functions and return pointers are stored at locations above the base pointer, and every other variable initilized inside the main() is stored at some location below the base pointer on the stack. You may view the below image to understand the analogy.

![stack2](https://i.imgur.com/ts1WhEn.png)

To answer the above questions, look at the disassembly of the main(). In <main+12>, we see an instruction `mov    DWORD PTR [rbp-0x4],0x0`. What does this mean? So basically when you use a `DWORD PTR` to move some value into a certain memory location, your are only moving the last 4 bytes into that particular location. Which means that, the last 4 bytes at memory location `rbp-0x4` will contain `0x0`. In later part of the code i.e in <main+53> we see a compare instruction 
`cmp    DWORD PTR [rbp-0x4],0x0`. This inherently means that the vale at location `rbp-0x4` is being compared with `0x0`. If the value remains unaltered, then it jumps to <main+73> as seen at instruction <main+57>. This looks somewhat similar to `if-else` condition in the C program, wherein we check if the `auth` is 0 (i.e false) or 1 (i.e true). Therefore, we may conclude that our variable `auth` is stored at location `rbp-0x4`.

- The `printf` in <main+31> prints out `Enter the passphrase` to the screen. 
- The next instruction i.e at <main+36> we see that the address of the location `rbp-0x20` is taken as the second argument to gets() i.e since it is stored in rdi, and rdi contains the second argument to any function call, for a 64-bit architecture. Therefore, it is safe to assume that our input data will be read into location `rbp-0x20` and will continue to grow the stack from that location onwards. 
- Since there is no limit to the number of characters that gets reads, we shall try to overwrite the location `rbp-0x4` in order to pass the compare statement condition in the next line. i.e `cmp    DWORD PTR [rbp-0x4],0x0`

### Step 3:
Form the payload:
- Once we have the locations, our `offset = 0x20 - 0x4`. Since stack size is 0x20, we must be careful as to not to overwrite `rip` which is present at location `rbp+0x8`. 
- Also the value at location `rbp-0x4` must be changed to anything other than '0'. To do that, our `payload  = 'a'*(0x20 - 0x4) + 'b'*0x1`. The size of this payload is less than `0x28 + 0x8( for rip)`, and therefore we need not fear the program crashing at a random address. 
- To understand better, set a break point at the `cmp` statement. i.e `b* 0x00000000004011ab`
- Upon giving the above payload, we see that

![context](https://i.imgur.com/DDjTgPx.png)
![locations](https://i.imgur.com/E0GphKh.png)

As we can see, the program stops at the break point at the compare statement. The value at variable `auth` or the value at location `rbp-0x4`, is equal to `0x62` instead of `0`. Why is this so? 
    If we see our payload, we are filling up the stack with 'a' s until rbp-0x4. rbp-0x4 contains 0x62 which is the hex for 'b'. Thus we have changed the value at memory `rbp-0x4`. 
    
As you might have noticed, the end of our string is "aaaab" but in memory, its represented as 0x6261616161 which would be "baaaa" if converted to ASCII characters. The data is stored in memory like this because of Endianness, specifically little-endian. On little-endian systems bytes are written from lower to higher addresses (in simple terms, left to right).

### Step 4:
Building exploit:
```python=
from pwn import *
p = process('./chall')
gdb.attach(p, gdbscript='''b*0x4011ab     # to check value at rbp-0x4, we can attach gdb to the process to debug.
c
''')
payload = 'a'*(0x20 - 0x4) + 'b'
p.sendline(payload)
p.interactive()
```
Upon running of the program we see,
```
Enter the passphrase: aaaaaaaaaaaaaaaaaaaaaaaaaaaab
Access granted!
```
