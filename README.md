# 0xarctos.github.io

CTF write-ups. One write-up = one commented Python solve script.

## Add a write-up

Drop the script in `src/writeups/<Event>/` (e.g. `src/writeups/WolvCTF_2026/blue_market.py`).
It must start with a docstring holding its metadata:

```python
"""
title: Blue Market
ctf: WolvCTF 2026
category: pwn
difficulty: 1                # 1 (very easy) to 5 (insane)
arch: amd64                  # pwntools name: amd64, i386, aarch64, arm...
linking: dynamic             # static | dynamic
mitigation_gaps: [no-pie, no-canary, partial-relro]   # [] if fully hardened
vulnerabilities: [stack-overflow]   # bugs found and exploited, at least one
tags: [ret2win, rop]
---
Optional notes in Markdown, shown above the script.
"""
```

- All keys above are required (except the notes after `---`); any other key is an error.
- Every tag must be listed in `src/writeups/tags.yml`: add new tags there first.
- The arch must be listed in `src/writeups/archs.yml`.
- Every mitigation gap must be listed in `src/writeups/mitigations.yml`.
- Every vulnerability must be listed in `src/writeups/vulnerabilities.yml`.

That is all: the page `/writeups/wolvctf-2026/blue-market/`, the sidebar entry and the
search page (`/writeups/`, filter by tags and min difficulty) are generated from it.
The docstring is not shown in the displayed script. A wrong metadata fails the build
with an explicit message.
