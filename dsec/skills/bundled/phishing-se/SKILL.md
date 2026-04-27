# SKILL: Phishing and Social Engineering

## Description
Phishing campaign design, payload delivery, and social engineering assessment methodology.

## Trigger Phrases
phishing, social engineering, spearphish, credential harvest, pretexting, vishing

## Methodology

### Phase 1: OSINT for Targeting
1. Enumerate employees: LinkedIn, Hunter.io, theHarvester
2. Email format discovery: `{first}.{last}@domain.com`
3. Check email security: `dig txt <domain>` (SPF/DKIM/DMARC)
4. Technology stack: Wappalyzer, BuiltWith
5. Recent events/news for pretext development

### Phase 2: Infrastructure Setup
1. Domain registration: typosquatting, homoglyph domains
2. SSL certificate: Let's Encrypt
3. Email server: `gophish` setup
4. Landing page: clone target login page
5. Configure SPF/DKIM for sending domain

### Phase 3: Payload Development
1. **Credential harvesting**: Cloned login page with POST capture
2. **Macro documents**: Office macro with download cradle
3. **HTA files**: HTML Application with embedded payload
4. **Link-based**: OAuth consent phishing, URL redirect abuse
5. **QR code**: QR phishing (quishing)

### Phase 4: Execution & Tracking
1. Send test emails, verify delivery
2. Monitor open rates, click rates, credential captures
3. Track user-agent, IP, timestamp
4. Follow-up waves with refined pretexts
