---
title: Spotting common vulnerabilities
description: The common memory-corruption bug classes and how to recognise them in decompiled code.
sidebar:
  order: 3
---

Most pwn challenges come down to recognising a familiar bug class in the decompiled code. This page lists the common ones, the patterns that give them away, and where each one leads. Read it with the binary open in Ghidra and the functions that handle **user input** as your starting point.

## Dangerous functions to grep for

A quick first pass: look at the imports and search for calls that write without a bound or format without a fixed string.

| Function | Problem |
| --- | --- |
| `gets` | Unbounded read into a buffer. Always a bug. |
| `scanf("%s", ...)`, `sscanf` | `%s` with no width reads until whitespace, unbounded. |
| `strcpy`, `strcat`, `sprintf` | Copy/concatenate with no destination size. |
| `read`, `fgets`, `memcpy`, `strncpy` | Safe only if the size is correct; check where it comes from. |
| `printf(user)`, `fprintf`, `snprintf` | A format string controlled by the user. |
| `malloc`/`free` usage | Look for double frees, use-after-free, missing size checks. |
| `system`, `exec*`, `popen` | Command execution, dangerous if the argument is influenced. |

## Stack buffer overflow

A write into a stack buffer larger than its size, reaching the saved registers and return address.

**Clues in the decompiler:**

- a fixed-size local like `char buf[64]` passed to `gets`, `read`, `scanf("%s")`, `strcpy`;
- a `read`/`memcpy` whose length is a constant **bigger** than the buffer, or a length that comes from user input;
- a loop copying bytes with an index that is not bounded by the buffer size.

**Leads to:** overwriting the return address. See [Know your stack](/pwn/the_stack/) for the offset, then [Defeating mitigations](/pwn/defeating_mitigations/).

## Format string

A `printf`-family call whose format argument is user-controlled (`printf(buf)` instead of `printf("%s", buf)`).

**Clues:** user input reaches the **first** argument of a `printf`-family function. In Ghidra the call has a single argument where a format literal should be.

**Leads to:**

- `%p` / `%x` / `%s` to **leak** stack and memory (defeat PIE and canary, find libc);
- `%n` to **write** an arbitrary value to an arbitrary address (GOT overwrite, return address). Positional args like `%7$p` target a specific slot.

## Integer issues

Bugs where a value does not fit, or a signed/unsigned mismatch changes a comparison.

**Clues:**

- a size or index read as `int` then used where a `size_t` is expected, so a negative value becomes huge;
- `if (len <= size)` where `len` is signed: a negative `len` passes the check, then is used as a large unsigned length in `memcpy`/`read`;
- arithmetic on a length (`len - 1`, `len + header`) that can wrap around.

**Leads to:** an oversized copy (back to a buffer overflow) or an undersized allocation (heap overflow).

## Off-by-one and null-byte overflow

Writing one element past the end, often a single `\0`.

**Clues:** a loop condition using `<=` instead of `<`, or a manual terminator written at `buf[len]` after a full-length read. On the heap, a one-null-byte overflow into the next chunk's size field is the classic "poison null byte".

**Leads to:** overwriting the least-significant byte of a saved pointer or a heap chunk size.

## Out-of-bounds index

An array accessed with an index taken from the user without a bounds check (or only an upper-bound check, allowing negatives).

**Clues:** `array[idx]` where `idx` comes from input and the check is missing or one-sided (`if (idx > max)` but not `idx < 0`).

**Leads to:** arbitrary read/write relative to the array, often a direct primitive.

## Heap bugs

Appear in menu-driven challenges that `malloc`/`free` objects.

**Clues:**

- **Use-after-free:** a pointer is used after `free` without being cleared (no `ptr = NULL`).
- **Double free:** `free` called twice on the same pointer.
- **Null pointer not reset:** a freed slot still reachable from a global array.

**Leads to:** tcache/fastbin poisoning and arbitrary allocation. A separate topic from stack bugs.

## Uninitialized memory

A local or heap buffer used before being fully written.

**Clues:** a struct/buffer printed or sent back without every field being set; a `malloc` (not `calloc`) whose contents are returned to the user.

**Leads to:** an **info leak** of stale stack/heap data (addresses, canary).

## Command injection and unsafe calls

Less common in pure pwn but frequent in "misc" and jails.

**Clues:** user input concatenated into a `system`/`popen` string, or a path/filename taken from input and opened directly.

**Leads to:** direct command execution or arbitrary file read.

## Workflow

1. Find the functions that read user input.
2. Follow that input: where is it stored, with what size, and what is done with it.
3. Match the pattern to one of the classes above.
4. Confirm the primitive (overwrite what, read what), then cross-check the mitigations with [Reading checksec](/kb/reading_checksec/).
