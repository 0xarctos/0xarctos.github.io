---
title: Reading checksec
description: What checksec reports about a binary, each protection and its possible values, and how to confirm them statically.
sidebar:
  order: 3
---

The `checksec` utility shows which compile-time protections are enabled on a binary. Reading it is a standard recon step for both exploitation and reverse engineering: it tells you how the binary was built and what to expect in the disassembly.

```bash
$ checksec ./binary
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

This page explains **what each field is**. For what each protection means when exploiting a binary, see [Defeating mitigations](/pwn/defeating_mitigations/).

## Arch

The architecture and endianness, e.g. `amd64-64-little` (64-bit x86, little-endian) or `i386-32-little` (32-bit). It determines register names, calling convention and address size. See [Architectures Specificities](/kb/architectures_specificities/).

## RELRO

*Relocation Read-Only* controls whether the GOT (Global Offset Table) can be written to at runtime. The GOT holds the resolved addresses of library functions.

| Value | Meaning |
| --- | --- |
| **No RELRO** | The GOT and `.init_array` are writable. |
| **Partial RELRO** | Some sections are read-only, but `.got.plt` stays writable. The common default. |
| **Full RELRO** | The whole GOT is resolved at startup and made read-only. |

## Stack canary

A random value placed between the local variables and the saved return address. A protected function checks it before returning; if a buffer overflow changed it, the program aborts with `*** stack smashing detected ***`.

| Value | Meaning |
| --- | --- |
| **No canary found** | No function in the binary uses a stack canary. |
| **Canary found** | At least one function uses a stack canary. |

:::caution
`Canary found` only means **at least one** function in the binary has a canary. It does **not** guarantee that every function is protected. Check the specific function you care about for the usual clues:

* a read from `fs:0x28` (x86-64) or `gs:0x14` (x86) early in the function, stored in a local variable;
* a comparison of that local against `fs:0x28` just before `return`;
* a call to `__stack_chk_fail`.
:::

:::note
* The canary's least-significant byte is always `\x00` to stop string-based leaks.
* The canary value is chosen randomly at startup and does not change during the binary's lifetime.
:::

## NX

*No-eXecute* (also `DEP`, marked `W^X`) marks the stack and heap as non-executable.

| Value | Meaning |
| --- | --- |
| **NX disabled** | Writable memory such as the stack can also be executed. |
| **NX enabled** | The stack and heap cannot be executed. |

## PIE

*Position-Independent Executable* randomizes the base address of the binary itself (ASLR already randomizes libraries, stack and heap).

| Value | Meaning |
| --- | --- |
| **No PIE** | The binary loads at a fixed address (`0x400000` on x86-64). |
| **PIE enabled** | The base address is randomized on each run; only the low 12 bits (page offset) are fixed. |

## Stripped

Whether the symbol table was removed.

| Value | Meaning |
| --- | --- |
| **No** | Function and variable names are kept. Ghidra/IDA show `main`, `win`, `managerOverride`... |
| **Yes** | No names; a decompiler shows raw addresses and auto-generated names. |

## FORTIFY

Whether the compiler replaced risky libc calls (`memcpy`, `sprintf`, `strcpy`) with bounds-checked `_chk` variants.

| Value | Meaning |
| --- | --- |
| **No** | Standard libc calls, no runtime bounds checks. |
| **Yes** | Some calls are bounds-checked at runtime. The `Fortifiable` count hints at how many calls could have been protected. |

## RWX segments

Whether any segment is readable, writable *and* executable at the same time.

| Value | Meaning |
| --- | --- |
| **No RWX segments** | Standard `W^X`: no segment is both writable and executable. |
| **Has RWX** | At least one segment is writable and executable. |
