---
title: Architectures Specificities
description: Major CPU architectures and the differences that matter for pwn and reverse - calling conventions, syscalls, return addresses.
sidebar:
  order: 1
---

Quick reference for the architectures you meet in CTFs. Conventions below are **Linux / System V**; Windows x64 and bare-metal differ.

## Calling conventions

Where integer/pointer arguments go, where the return value lands, and how the return address is stored.

| Arch | Arg registers (then stack) | Return | Return address |
| --- | --- | --- | --- |
| **x86 (i386)** | *(all on the stack)* | `eax` | on the stack |
| **x86-64 (amd64)** | `rdi rsi rdx rcx r8 r9` | `rax` | on the stack |
| **ARM32 (AArch32)** | `r0 r1 r2 r3` | `r0` | `lr` (saved on stack if nested) |
| **ARM64 (AArch64)** | `x0 x1 x2 x3 x4 x5 x6 x7` | `x0` | `x30` / `lr` (saved on stack if nested) |
| **MIPS (o32)** | `a0 a1 a2 a3` | `v0` | `ra` ($31) |
| **RISC-V (rv64)** | `a0 ... a7` | `a0` | `ra` (x1) |

The big split: on **x86 / x86-64** the return address lives on the stack, so a stack overflow reaches it directly. On **ARM / MIPS / RISC-V** the return address is a **register** (`lr`/`ra`); a leaf function keeps it there, but any function that calls another pushes it to the stack in its prologue: that saved copy is your overflow target.

## Syscalls

| Arch | Instruction | Syscall number | Syscall args |
| --- | --- | --- | --- |
| **x86** | `int 0x80` | `eax` | `ebx ecx edx esi edi ebp` |
| **x86-64** | `syscall` | `rax` | `rdi rsi rdx r10 r8 r9` |
| **ARM32** | `svc #0` | `r7` | `r0 ... r6` |
| **ARM64** | `svc #0` | `x8` | `x0 ... x5` |
| **MIPS** | `syscall` | `v0` | `a0 ... a3` |
| **RISC-V** | `ecall` | `a7` | `a0 ... a5` |

:::note
On **x86-64**, syscall args use `r10` where the *function* convention uses `rcx` (the `syscall` instruction clobbers `rcx`). Easy to get wrong when writing ROP that does a raw syscall.
:::

## Registers & stack

| Arch | Stack ptr | Frame ptr | Address size |
| --- | --- | --- | --- |
| x86 | `esp` | `ebp` | 4 bytes | 
| x86-64 | `rsp` | `rbp` | 8 bytes |
| ARM32 | `sp` (r13) | `fp` (r11) | 4 bytes |
| ARM64 | `sp` | `x29` | 8 bytes | 
| MIPS | `sp` ($29) | `fp` ($30) | 4 bytes (mips32) | 

The stack grows **downward** (towards lower addresses) on all of these.

## Endianness

How a multi-byte value is laid out in memory. Little-endian stores the low byte first, so the value `0x41424344` is laid out in memory as the bytes `44 43 42 41`.

| Arch | Endianness |
| --- | --- |
| x86 / x86-64 | Little |
| ARM32 / ARM64 | Little (usual config, can be big) |
| RISC-V | Little |
| MIPS | Both: `mips` = big, `mipsel` = little |

## Per-arch gotchas

- **x86-64**: `call` requires the stack **16-byte aligned**. ROP chains that call libc (e.g. `system`) may crash in a `movaps`; add a bare `ret` gadget to realign. 32-bit has no such rule.
- **ARM (32-bit)**: has **Thumb** mode (16-bit instructions). The low bit of a code address selects the mode: a jump target with bit 0 set runs as Thumb. Disassemble in the right mode or everything looks like garbage.
- **MIPS**: **branch delay slot**: the instruction *after* a branch/jump executes before the jump takes effect. Account for it when reading disassembly and when building shellcode.
- **ARM64**: pointer authentication (PAC) and BTI appear on newer targets; signed pointers break naive address reuse.
