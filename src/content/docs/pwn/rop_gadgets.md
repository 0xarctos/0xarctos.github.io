---
title: Finding ROP gadgets
description: What a gadget is, the tools to search for them, and the useful ones to control registers and syscalls.
sidebar:
  order: 5
---

When NX is enabled you cannot run your own shellcode, so you reuse small slices of existing executable code called **gadgets**. A gadget is a short sequence ending in `ret` (or `jmp`/`call` to a register). By chaining their addresses on the stack, each `ret` runs the next one, letting you set registers and call functions. See [Know your stack](/pwn/the_stack/) for why the stack drives this, and [Defeating mitigations](/pwn/defeating_mitigations/) for when ROP is the answer.

## Tools

`ROPgadget` is enough:

```bash
ROPgadget --binary ./prog                      # list every gadget
ROPgadget --binary ./prog | grep 'pop rdi'     # find a specific one
```

By default `ROPgadget` collapses duplicate gadgets to a single address. Use `--all` to list **every** occurrence, including identical gadgets at different offsets:

```bash
ROPgadget --binary ./prog --all | grep ': pop rdi ; ret'
```

This matters when you want to pick the occurrence at a **particular offset**, for example the one whose address is closest to a value you already control, to shrink the brute force on the unknown bits.

:::tip
`pwntools` can also find gadgets and build chains (`ROP(elf)`, `rop.find_gadget(...)`, `rop.call(...)`). It is convenient but I do not recommend it for gadget hunting: you miss alternative gadgets and chains far more easily than when you search by hand. Use it to assemble a chain you already understand, not to discover it.
:::

:::note
Gadgets must come from an **executable, non-randomised** region. With `No PIE`, the binary's own gadgets have fixed addresses. With PIE or when you need libc gadgets, you first need a [leak](/pwn/defeating_mitigations/) to know the base, then add it to each gadget offset.
:::

## Useful gadgets (x86-64 System V)

Arguments go in `rdi, rsi, rdx, rcx, r8, r9`, so the goal is usually to pop values into those registers before a call. See [Architectures Specificities](/kb/architectures_specificities/) for other ABIs.

| Gadget | Use |
| --- | --- |
| `pop rdi ; ret` | Set the 1st argument. The most wanted gadget. |
| `pop rsi ; ret` | Set the 2nd argument (often only as `pop rsi ; pop r15 ; ret`). |
| `pop rdx ; ret` | Set the 3rd argument (rarer in small binaries). |
| `pop rax ; ret` | Set the syscall number. |
| `syscall ; ret` | Make a raw syscall (args in `rdi rsi rdx r10 r8 r9`). |
| `ret` | A bare `ret`, used to fix 16-byte stack alignment before a libc call. |
| `leave ; ret` | Stack pivot (set `rsp` from `rbp`). |
| `mov [rdi], rsi ; ret` (or similar) | Arbitrary write primitive. |

## When the gadgets are missing

- **ret2csu**: `__libc_csu_init` contains a generic gadget sequence that pops `rbx, rbp, r12, r13, r14, r15` and can set `rdx`/`rsi`. Useful when there is no direct `pop rdx`. Present in many dynamically linked binaries built before glibc dropped it.
- **libc gadgets**: once you leak libc, it has far more gadgets than the challenge binary. Search them in the matching `libc.so.6` with the same tools.

## Stack alignment gotcha

On x86-64 the ABI requires `rsp` to be 16-byte aligned at a `call`. A ROP chain that calls a libc function (e.g. `system`) can crash inside a `movaps` if the stack is misaligned. The fix is to insert one extra bare `ret` gadget before the call to realign.
