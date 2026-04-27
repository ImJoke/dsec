# SKILL: CTF Binary Exploitation (Pwn)

## Description
Binary exploitation methodology for CTF challenges.

## Trigger Phrases
pwn, binary, exploit, buffer overflow, rop, shellcode, gdb, pwntools

## Methodology

### Initial Analysis
1. `file <binary>` — architecture, linking, stripped?
2. `checksec <binary>` — NX, PIE, canary, RELRO
3. `strings <binary>` — interesting strings, format strings
4. Open in Ghidra/IDA — find main, vulnerable functions

### Stack Buffer Overflow
1. Find overflow: pattern create → crash → pattern offset
2. Control EIP/RIP: overwrite return address
3. NX disabled → shellcode on stack, jump to it
4. NX enabled → ROP chain: `ROPgadget --binary <file>`
5. ret2libc: leak libc address → system("/bin/sh")

### Format String
1. Test: `%x %x %x %x` — leaks stack values
2. Read: `%n$s` — read from arbitrary address
3. Write: `%n` — write to arbitrary address (GOT overwrite)

### Heap Exploitation
1. Use-after-free, double-free, heap overflow
2. Tcache poisoning (glibc 2.26+): overwrite fd pointer
3. Fastbin dup, unsorted bin attack

### Tools
- pwntools: `from pwn import *`
- GDB + pwndbg/GEF
- ROPgadget, one_gadget
- LibcSearcher for remote libc identification
