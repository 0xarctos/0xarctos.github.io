---
title: Strings
description: Finding readable text inside a binary with strings or Ghidra, and using it as a lead.
sidebar:
  order: 2
---

Readable text baked into a binary is one of the fastest recon wins. It often leaks flags, file paths, format strings, prompts, error messages, embedded credentials, or the names of functions the program calls. Checking strings is usually the first thing to do after `file` and `checksec`.

## With `strings`

`strings` prints sequences of printable characters found in a file.

```bash
strings ./binary
```

Useful options:

| Option | What it does |
| --- | --- |
| `-n <len>` | Minimum length to report (default 4). `-n 8` cuts noise. |
| `-t x` | Show the **offset** of each string (here in hex). Handy to locate it in a hex editor or disassembler. |
| `-a` | Scan the **whole file**, not just the loaded/data sections. |
| `-e l` / `-e b` | Decode **16-bit wide** strings (UTF-16 little/big endian), common in Windows binaries. |

Using it in combinaison of ``grep`` allows to search for specific keyword, like ``flag``.

:::caution
`strings` only finds **printable, contiguous** bytes. It misses obfuscated, XOR-encoded, or runtime-built strings (assembled byte by byte, decrypted at startup). Not finding a keyword with `strings` does not mean it is not there.
:::

## With Ghidra

Ghidra resolves strings into the code, which `strings` alone cannot do: you see not just the text but **where it is used**.

- **Window > Defined Strings** lists every string Ghidra identified, with its address and the section it lives in.
- **Search > For Strings...** rescans with your own minimum length and encoding, useful when a string was not auto-detected.
- Click a string, then look at its **references** (right-click, *References > Show References to Address*, or press `Ctrl+Shift+F`). This jumps to the code that uses it, which is often the interesting function (the one printing the flag, checking a password, building a command).

That last step is the real advantage: a bare string from `strings` is a hint, but a cross-reference turns it into a path straight to the relevant logic.

