---
title: Defeating mitigations
description: What each binary protection means for exploitation and which technique it forces you into.
sidebar:
  order: 4
---

Once you have read the protections with `checksec` (see [Reading checksec](/kb/reading_checksec/) for what each field is), this page covers what they mean when you actually exploit the binary. Each protection you face removes a technique and pushes you towards another.

## RELRO

RELRO decides whether a **GOT overwrite** is on the table (redirecting a library call to an attacker-chosen address by writing its GOT entry).

| Value | Implication |
| --- | --- |
| **No RELRO** | Easiest case: overwrite any GOT entry freely. |
| **Partial RELRO** | `.got.plt` is still writable, so a GOT overwrite is still possible. |
| **Full RELRO** | GOT overwrite is impossible; pivot to other targets (hooks, `__exit_funcs`, saved return addresses). |

## Stack canary

| Value | Implication |
| --- | --- |
| **No canary** | A straight stack buffer overflow can reach the saved return address. |
| **Canary present** | You must **leak the canary** and replace it in the payload, or avoid overwriting it. |

Ways to deal with a canary:

- **Leak it**: a format string bug, an uninitialized read, or an out-of-bounds read that exposes the canary word.
- **Brute force it** on a `fork`-based server: the canary is constant across forks, so you can recover it one byte at a time (256 tries per byte, the first byte is `\x00`).
- **Avoid it**: overwrite a pointer or use a primitive that does not cross the canary (e.g. a partial overwrite, or an arbitrary write instead of a linear overflow).

## NX

| Value | Implication |
| --- | --- |
| **NX disabled** | Place shellcode on the stack and jump to it. |
| **NX enabled** | Stack/heap shellcode will not run. Reuse existing executable code instead: **ret2libc**, **ROP**, `ret2plt`, `ret2dlresolve`. |

## PIE

| Value | Implication |
| --- | --- |
| **No PIE** | Addresses of gadgets, functions and the GOT are fixed (`0x400000` base): hardcode them. |
| **PIE enabled** | You need an **address leak** before using any binary address. Because only the low 12 bits are fixed, a partial overwrite of a saved pointer is sometimes enough. |

## Stripped

Stripping does not change exploitability, only effort: with no symbols you recover function boundaries and names yourself in the decompiler. It matters for finding your target (a `win` function, the vulnerable call), not for the technique.

## RWX segments

A readable-writable-executable segment is a gift even when NX is enabled elsewhere: write shellcode into it and jump there, skipping ROP entirely.

## Putting it together

The easiest target is `No RELRO / No canary / NX disabled / No PIE`. Each protection enabled narrows your options:

- **No canary + No PIE**: classic stack overflow to a fixed `ret2win` or ROP chain.
- **NX enabled**: no shellcode, go ROP / ret2libc.
- **PIE enabled**: find a leak first.
- **Full RELRO**: forget GOT overwrite, target hooks or saved return addresses.
