# SKILL: OSINT Social Media Crawling

## Description
API-less social media OSINT with ReAct methodology for deep understanding.

## Trigger Phrases
osint, twitter, telegram, social media, recon, dork, mastodon

## Methodology

### Twitter/X (API-less via Nitter)
1. Use `osint_crawl_twitter` tool with targeted queries
2. Search operators: `from:user`, `to:user`, `since:2024-01-01`, `filter:links`
3. ReAct: Don't just read — ANALYZE sentiment, connections, timeline patterns
4. Follow reply chains for context
5. Cross-reference usernames across platforms

### Telegram (API-less via t.me/s/)
1. Use `osint_crawl_telegram` tool for public channels
2. Key infosec channels: vx-underground, darknet intelligence, exploit alerts
3. Track forwarded messages to find original sources
4. Monitor for IOCs, leaked credentials, exploit announcements

### Google Dorking
1. `site:target.com filetype:pdf|doc|xls`
2. `inurl:admin|login|dashboard site:target.com`
3. `"password" | "secret" | "api_key" filetype:env|json|yaml`
4. Use `web_search` tool with dork queries

### Infosec News
1. Monitor: The Hacker News, BleepingComputer, Krebs on Security
2. CVE tracking: nvd.nist.gov, cvedetails.com
3. Exploit tracking: exploit-db.com, PacketStorm
