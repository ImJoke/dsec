# SKILL: Static Code Analysis (Trail of Bits inspired)

## Description
Automated and manual static analysis for vulnerability discovery across multiple languages.

## Trigger Phrases
code review, static analysis, semgrep, codeql, sast, source code, audit, vulnerability

## Methodology

### Phase 1: Setup
1. Identify language/framework: Python, Java, Go, JavaScript, C/C++, Rust
2. Install scanners: `pip install semgrep`, `npm install -g eslint-plugin-security`
3. Check for existing CI/CD security configs

### Phase 2: Automated Scanning
1. **Semgrep**: `semgrep --config=p/owasp-top-ten .`
2. **Semgrep security**: `semgrep --config=p/security-audit .`
3. **Bandit** (Python): `bandit -r . -ll`
4. **SpotBugs** (Java): `spotbugs -effort:max -textui target/classes`
5. **GoSec** (Go): `gosec ./...`
6. **ESLint security** (JS): `eslint --plugin security .`

### Phase 3: Manual Review Focus Areas
1. **Input validation**: SQL injection, XSS, command injection, path traversal
2. **Authentication**: Hardcoded credentials, weak password handling, session management
3. **Crypto**: Weak algorithms (MD5/SHA1), hardcoded keys, improper random
4. **Deserialization**: Unsafe pickle/yaml/json loading
5. **File operations**: Path traversal, symlink following, race conditions
6. **Memory safety** (C/C++): Buffer overflow, use-after-free, format strings

### Phase 4: Dependency Analysis
1. `pip-audit` (Python), `npm audit` (JS), `cargo audit` (Rust)
2. Check for known CVEs in dependencies
3. License compliance check
4. Look for typosquatting packages

### Phase 5: Reporting
1. Categorize by severity (Critical/High/Medium/Low)
2. Include PoC for each finding
3. Provide remediation guidance with code examples
