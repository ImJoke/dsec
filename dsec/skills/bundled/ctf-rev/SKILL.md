# SKILL: CTF Reverse Engineering

## Description
Reverse engineering workflow for CTF challenges.

## Trigger Phrases
reverse, reversing, ida, ghidra, disassemble, decompile

## Methodology

### Static Analysis
1. `file <binary>` — identify format
2. `strings -n 8 <binary>` — look for flag format, passwords
3. Open in Ghidra — decompile main, follow logic
4. Identify: encryption, encoding, anti-debug, obfuscation

### Dynamic Analysis
1. `ltrace ./binary` — library call trace
2. `strace ./binary` — system call trace
3. GDB: breakpoints at key comparisons
4. `angr` for symbolic execution on complex checks

### Common Patterns
- XOR cipher with known key → brute force key byte-by-byte
- Custom hash → z3 SMT solver
- VM-based obfuscation → trace opcode handlers
- Anti-debug: ptrace check, timing checks → patch or LD_PRELOAD
