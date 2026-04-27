# SKILL: Bug Bounty Reconnaissance & Exploitation

## Description
Bug bounty recon-to-exploitation methodology with noise management.

## Trigger Phrases
bug bounty, recon, subdomain, nuclei, burp, scope

## Methodology

### Phase 1: Scope & Recon
1. Define scope: domains, IPs, out-of-scope
2. Subdomain enum: `subfinder -d target.com -all -o subs.txt`
3. Live hosts: `httpx -l subs.txt -o live.txt`
4. Screenshot: `gowitness file -f live.txt`
5. Tech stack: `whatweb`, Wappalyzer

### Phase 2: Content Discovery
1. Dir brute: `feroxbuster -u https://target.com -w wordlist.txt`
2. JS analysis: `linkfinder -i https://target.com/app.js -o cli`
3. Parameter discovery: `arjun -u https://target.com/api/`
4. API endpoints: check /api/, /graphql, /swagger, /openapi.json

### Phase 3: Vulnerability Testing
1. Run nuclei: `nuclei -l live.txt -t nuclei-templates/ -severity critical,high`
2. Test auth: IDOR, broken access control, privilege escalation
3. Test input: SQLi, XSS, SSRF, SSTI, command injection
4. Business logic: rate limiting, race conditions, price manipulation

### Noise Management
- Keep detailed notes of every test → avoid re-testing
- Use graph_memory_insert to track tested endpoints
- If stuck on one approach, pivot to different attack surface
- Don't overthink — move to next target after reasonable effort
