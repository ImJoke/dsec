# SKILL: 0-Day Vulnerability Research

## Description
Methodology for discovering novel vulnerabilities in software.

## Trigger Phrases
0day, zero day, vulnerability research, fuzzing, cve, patch diffing

## Methodology

### Target Selection
1. Identify widely-used software with complex input parsing
2. Check recent patches — are there patterns of similar bugs?
3. Focus on: parsers, deserializers, auth logic, file handlers

### Code Auditing
1. Use `programmer_search` to find dangerous patterns:
   - C/C++: strcpy, sprintf, memcpy without bounds, use-after-free patterns
   - Python: eval, exec, pickle.loads, subprocess with shell=True
   - PHP: unserialize, include with user input, preg_replace with /e
   - Java: Runtime.exec, ObjectInputStream, JNDI lookup
2. Trace user input from entry point to dangerous sink
3. Check for integer overflows, type confusion, race conditions

### Fuzzing
1. Coverage-guided: AFL++, libFuzzer
2. Grammar-based: for complex formats (PDF, HTTP, SQL)
3. Mutation-based: for binary formats
4. Monitor: ASAN, MSAN, UBSAN for memory bugs

### Patch Diffing
1. Compare vulnerable vs patched versions: `diff`, BinDiff
2. Identify the fix — what was the root cause?
3. Check: is the fix complete? Are there variant bugs?
4. Look for similar patterns in other code paths

### Research Documentation
1. Use memory tools to save every finding
2. Build attack chain: trigger → control → impact
3. Write PoC: minimal reproducer
4. Calculate CVSS score, determine impact
