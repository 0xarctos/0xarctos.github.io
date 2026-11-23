---
title: Know your stack
description: How the stack is laid out at startup, how function frames work, and how to compute the overflow size needed to reach a target.
sidebar:
  order: 2
---

The stack grows **downward**: each push and each `call` moves the stack pointer towards **lower** addresses. Keeping that in mind, this page goes from the stack's initial layout to the frame of a single function, then to computing how many bytes an overflow needs to reach a given target.

Examples are **x86-64 Linux / System V**. The idea is identical on x86, only the sizes (4 vs 8 bytes) and register names change. See [Architectures Specificities](/kb/architectures_specificities/).

## Stack at program start

Before `main` runs, the kernel has already filled the bottom of the stack with the process startup data. From the **highest** address down to where `rsp` points at entry:

```text
  higher addresses
+---------------------------+
|  env strings  "PATH=..."  |   the actual bytes of the environment
|  arg strings  "./prog"    |   the actual bytes of argv
+---------------------------+
|  auxiliary vector (auxv)  |   key/value pairs from the kernel
|  NULL                     |
|  envp[n] ... envp[0]      |   pointers to the env strings above
|  NULL                     |
|  argv[argc-1] ... argv[0] |   pointers to the arg strings above
|  argc                     |   <-- rsp points here at _start
+---------------------------+
  lower addresses
```

Two practical consequences:

- **Environment and arguments are attacker-influenced data sitting on the stack.** You can place a known string there (an env var, an argv entry) and sometimes use its address, for example as a `/bin/sh` pointer.
- The exact addresses shift with the size of the environment, which is one source of stack address instability between machines.

## Function frames

When a function is called, the stack is organised into a **frame**. Two things build it:

1. The `call` instruction pushes the **return address** (the instruction right after the call).
2. The function **prologue** saves the caller's frame pointer and reserves space for locals:

```asm
push rbp            ; save caller's rbp
mov  rbp, rsp       ; rbp = frame base for this function
sub  rsp, 0x40      ; reserve 0x40 bytes for local variables
```

The frame then looks like this (higher addresses at the top):

```text
  higher addresses
+---------------------------+
|  caller's frame ...       |
|  argument 7+ (if any)     |   extra args the caller pushed
|  return address           |   rbp + 0x08   <-- overflow target for ret2...
|  saved rbp                |   rbp + 0x00   <-- rbp points here
+---------------------------+
|  canary (if present)      |   rbp - 0x08
|  local variables          |
|  char* buf_to_overflow    |   e.g. rbp - 0x40
+---------------------------+   <-- rsp (after sub)
  lower addresses
```

The **epilogue** undoes it: `leave` (which is `mov rsp, rbp ; pop rbp`) then `ret`, which pops the return address into `rip`. If you have overwritten that saved return address, `ret` jumps wherever you put it.

:::note
On x86-64 SysV, leaf functions may use the **red zone**: 128 bytes below `rsp` that they can scribble on without adjusting `rsp`. It rarely matters for a basic overflow but explains locals that seem to live past `rsp`.
:::

## Computing the overflow size

A linear buffer overflow writes **from your buffer upward, towards higher addresses**, overrunning whatever comes after it: the rest of the locals, the canary, the saved `rbp`, then the return address. To hit a target you need the exact distance from the start of your buffer to it.

### From the decompiler (static)

Read where the buffer sits relative to `rbp`. If Ghidra shows `buf` at `rbp-0x40` on x86-64:

```text
start of buf  ..........  rbp-0x40
to saved rbp  ..........  0x40 bytes of padding
saved rbp     ..........  + 8 bytes
return address .........  reached at offset 0x40 + 8 = 0x48
```

So `0x48` bytes of padding, then your 8-byte target address lands on the saved return address. If a canary sits at `rbp-0x08`, you cannot cross it blindly: you must preserve or leak it (see [Defeating mitigations](/pwn/defeating_mitigations/)).

### With a cyclic pattern (dynamic)

When you cannot or do not want to read offsets by hand, use a De Bruijn ("cyclic") pattern: every 4- or 8-byte window is unique, so the bytes that land in the crashing register tell you the offset directly.

```python
from pwn import cyclic, cyclic_find, process

p = process("./prog")
p.sendline(cyclic(200))
p.wait()
# read the faulting value (e.g. from the core dump or a debugger),
# then look it up:
offset = cyclic_find(0x6161616c)   # value found in rip/rsp
print(offset)
```

The returned `offset` is exactly the padding length to reach that spot. Command-line equivalents: `cyclic 200` and `cyclic -l <value>`.
