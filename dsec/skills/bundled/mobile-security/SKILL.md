# SKILL: Mobile Application Security

## Description
Android and iOS application security testing methodology.

## Trigger Phrases
mobile, android, ios, apk, ipa, frida, objection, jadx, smali, mobile pentest

## Methodology

### Phase 1: Static Analysis
1. **Android**: Decompile APK with `jadx -d output app.apk`
2. Check AndroidManifest.xml: exported components, permissions, debuggable flag
3. Search for hardcoded secrets: `grep -ri "api_key\|password\|secret" output/`
4. Check for insecure storage: SharedPreferences, SQLite databases
5. **iOS**: Use `class-dump` or Hopper for binary analysis

### Phase 2: Dynamic Analysis
1. Setup proxy: Burp Suite with cert installed on device
2. **Frida**: `frida -U -f <package> -l script.js`
3. SSL pinning bypass: `objection -g <package> explore` → `android sslpinning disable`
4. Root/jailbreak detection bypass
5. Hook crypto functions to capture keys

### Phase 3: Network Analysis
1. Intercept API calls, check for HTTP (not HTTPS)
2. Certificate pinning implementation check
3. WebSocket traffic analysis
4. Check for sensitive data in request/response

### Phase 4: Data Storage
1. Check `/data/data/<package>/` for sensitive files
2. Keychain dump (iOS): `objection explore` → `ios keychain dump`
3. Check backup flag: `android:allowBackup="true"`
4. Check for data in logs: `adb logcat | grep -i password`
