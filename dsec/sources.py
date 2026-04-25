"""
DSEC Research Sources
Scrapers/API clients for NVD, ExploitDB, GitHub Advisories, HackerOne,
GTFOBins, PortSwigger, PacketStorm, and CTFTime.
Each source exposes: async fetch(query, max_results) -> List[dict]
"""
import asyncio
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus

import httpx

TIMEOUT = httpx.Timeout(15.0, connect=8.0)
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
}


def _result(
    item_id: str,
    title: str,
    description: str = "",
    *,
    severity: str = "N/A",
    score: Optional[float] = None,
    url: str = "",
    **extra: Any,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "id": item_id,
        "title": title[:120],
        "description": description[:400],
        "severity": severity,
        "score": score,
        "url": url,
    }
    result.update(extra)
    return result


# ---------------------------------------------------------------------------
# NVD – National Vulnerability Database (REST API v2)
# ---------------------------------------------------------------------------

async def fetch_nvd(query: str, max_results: int = 5) -> List[Dict]:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": query, "resultsPerPage": min(max_results, 10)}
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as client:
            resp = await client.get(url, params=params)
            if resp.status_code != 200:
                return []
            data = resp.json()
            results: List[Dict] = []
            for vuln in data.get("vulnerabilities", [])[:max_results]:
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")
                descs = cve.get("descriptions", [])
                desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                # CVSS score
                metrics = cve.get("metrics", {})
                score: Optional[float] = None
                severity = "UNKNOWN"
                for mt in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    ml = metrics.get(mt, [])
                    if ml:
                        cvss_data = ml[0].get("cvssData", {})
                        score = cvss_data.get("baseScore")
                        severity = (
                            ml[0].get("baseSeverity")
                            or cvss_data.get("baseSeverity", "UNKNOWN")
                        )
                        break
                refs = cve.get("references", [])
                ref_url = refs[0].get("url", "") if refs else ""
                results.append(
                    _result(
                        cve_id,
                        f"{cve_id} – {desc[:100]}",
                        desc,
                        severity=(severity or "UNKNOWN").upper(),
                        score=score,
                        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        reference_url=ref_url,
                    )
                )
            return results
    except Exception:
        return []


# ---------------------------------------------------------------------------
# ExploitDB (search via JSON endpoint)
# ---------------------------------------------------------------------------

async def fetch_exploitdb(query: str, max_results: int = 5) -> List[Dict]:
    url = "https://www.exploit-db.com/search"
    params = {"q": query, "action": "search"}
    json_headers = {**HEADERS, "X-Requested-With": "XMLHttpRequest",
                    "Accept": "application/json, text/javascript, */*; q=0.01"}
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, headers=json_headers,
                                     follow_redirects=True) as client:
            resp = await client.get(url, params=params)
            if resp.status_code != 200:
                return []
            try:
                data = resp.json()
            except Exception:
                return _parse_exploitdb_html(resp.text, max_results)
            items = data.get("data", []) or data.get("results", [])
            results: List[Dict] = []
            for item in items[:max_results]:
                edb_id = item.get("id", "") or item.get("edb_id", "")
                title = item.get("description", "") or item.get("title", "")
                date = item.get("date_published", "") or item.get("date", "")
                etype = item.get("type", {})
                if isinstance(etype, dict):
                    etype = etype.get("name", "")
                platform = item.get("platform", {})
                if isinstance(platform, dict):
                    platform = platform.get("name", "")
                results.append(
                    _result(
                        f"EDB-{edb_id}",
                        title,
                        f"Type: {etype} | Platform: {platform} | Date: {date}",
                        url=f"https://www.exploit-db.com/exploits/{edb_id}",
                    )
                )
            return results
    except Exception:
        return []


def _parse_exploitdb_html(html: str, max_results: int) -> List[Dict]:
    """Fallback HTML parser for ExploitDB."""
    results: List[Dict] = []
    try:
        from bs4 import BeautifulSoup  # type: ignore
        soup = BeautifulSoup(html, "html.parser")
        rows = soup.select("table#exploits-table tbody tr")
        for row in rows[:max_results]:
            cols = row.find_all("td")
            if len(cols) < 5:
                continue
            edb_id = cols[0].get_text(strip=True)
            title_el = cols[4].find("a")
            title = title_el.get_text(strip=True) if title_el else cols[4].get_text(strip=True)
            date = cols[2].get_text(strip=True)
            results.append(
                _result(
                    f"EDB-{edb_id}",
                    title,
                    f"Date: {date}",
                    url=f"https://www.exploit-db.com/exploits/{edb_id}",
                )
            )
    except ImportError:
        pass
    except Exception:
        pass
    return results


# ---------------------------------------------------------------------------
# GitHub Security Advisories (REST v3)
# ---------------------------------------------------------------------------

async def fetch_github_advisories(query: str, max_results: int = 5) -> List[Dict]:
    url = "https://api.github.com/advisories"
    params = {"query": query, "per_page": min(max_results, 10)}
    gh_headers = {**HEADERS, "Accept": "application/vnd.github+json",
                  "X-GitHub-Api-Version": "2022-11-28"}
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, headers=gh_headers) as client:
            resp = await client.get(url, params=params)
            if resp.status_code != 200:
                return []
            items = resp.json()
            if not isinstance(items, list):
                items = items.get("advisories", [])
            results: List[Dict] = []
            for item in items[:max_results]:
                ghsa = item.get("ghsa_id", "")
                summary = item.get("summary", "")[:120]
                severity = (item.get("severity") or "UNKNOWN").upper()
                cvss = item.get("cvss", {}) or {}
                score = cvss.get("score")
                html_url = item.get("html_url", f"https://github.com/advisories/{ghsa}")
                results.append(
                    _result(
                        ghsa,
                        f"{ghsa} – {summary}",
                        item.get("description", ""),
                        severity=severity,
                        score=score,
                        url=html_url,
                    )
                )
            return results
    except Exception:
        return []


# ---------------------------------------------------------------------------
# HackerOne Disclosed Reports (GraphQL)
# ---------------------------------------------------------------------------

async def fetch_hackerone_disclosed(query: str, max_results: int = 5) -> List[Dict]:
    url = "https://hackerone.com/graphql"
    gql_query = """
    query HacktivitySearch($query: String!, $size: Int) {
      search(index: CompleteHacktivityReportIndex, query_string: $query,
             from: 0, size: $size,
             sort: {field: "latest_disclosable_activity_at", direction: DESC}) {
        nodes {
          ... on HacktivityDocument {
            _id
            disclosed_at
            report {
              title
              severity_rating
              url
              currency
              bounty_amount
            }
          }
        }
      }
    }
    """
    payload = {"query": gql_query, "variables": {"query": query, "size": max_results}}
    h1_headers = {
        **HEADERS,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Auth-Token": "",
    }
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, headers=h1_headers) as client:
            resp = await client.post(url, json=payload)
            if resp.status_code != 200:
                return []
            data = resp.json()
            nodes = (
                data.get("data", {})
                .get("search", {})
                .get("nodes", [])
            )
            results: List[Dict] = []
            for node in nodes[:max_results]:
                rep = node.get("report", {}) or {}
                title = rep.get("title", "")[:120]
                severity = (rep.get("severity_rating") or "unknown").upper()
                bounty = rep.get("bounty_amount")
                currency = rep.get("currency", "USD")
                rep_url = rep.get("url", "")
                if not rep_url.startswith("http"):
                    rep_url = "https://hackerone.com" + rep_url
                results.append(
                    _result(
                        node.get("_id", ""),
                        title,
                        f"Severity: {severity}" + (f" | Bounty: {bounty} {currency}" if bounty else ""),
                        severity=severity,
                        url=rep_url,
                        disclosed_at=node.get("disclosed_at", ""),
                    )
                )
            return results
    except Exception:
        return []


# ---------------------------------------------------------------------------
# GTFOBins (GitHub raw markdown)
# ---------------------------------------------------------------------------

async def fetch_gtfobins(binary: str, max_results: int = 5) -> List[Dict]:
    binary_lower = binary.lower().strip()
    raw_url = (
        f"https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io"
        f"/master/_gtfobins/{binary_lower}.md"
    )
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as client:
            resp = await client.get(raw_url)
            if resp.status_code == 404:
                return []
            if resp.status_code != 200:
                return []
            content = resp.text

        techniques: List[str] = []
        current_section = ""
        section_lines: List[str] = []

        for line in content.splitlines():
            if line.startswith("## "):
                if current_section and section_lines:
                    techniques.append((current_section, "\n".join(section_lines[:15])))
                current_section = line[3:].strip()
                section_lines = []
            elif current_section:
                section_lines.append(line)

        if current_section and section_lines:
            techniques.append((current_section, "\n".join(section_lines[:15])))

        results: List[Dict] = []
        for sec_name, sec_content in techniques[:max_results]:
            results.append(
                _result(
                    f"GTFOBins:{binary_lower}:{sec_name.lower().replace(' ', '_')}",
                    f"GTFOBins – {binary} [{sec_name}]",
                    sec_content,
                    severity="PRIV_ESC",
                    url=f"https://gtfobins.github.io/gtfobins/{binary_lower}/",
                )
            )
        return results
    except Exception:
        return []


# ---------------------------------------------------------------------------
# PortSwigger Web Security Academy
# ---------------------------------------------------------------------------

async def fetch_portswigger(query: str, max_results: int = 5) -> List[Dict]:
    url = "https://portswigger.net/web-security/all-topics"
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS,
                                     follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return []
            html = resp.text

        query_lower = query.lower()
        results: List[Dict] = []
        try:
            from bs4 import BeautifulSoup  # type: ignore
            soup = BeautifulSoup(html, "html.parser")
            links = soup.find_all("a", href=True)
            for link in links:
                href = link["href"]
                text = link.get_text(strip=True)
                if not text or not href:
                    continue
                if query_lower in text.lower() or query_lower in href.lower():
                    full_url = href if href.startswith("http") else "https://portswigger.net" + href
                    results.append(
                        _result(
                            f"PS:{href}",
                            text,
                            f"PortSwigger Web Security Academy – {text}",
                            severity="EDUCATIONAL",
                            url=full_url,
                        )
                    )
                    if len(results) >= max_results:
                        break
        except ImportError:
            # Fallback regex
            pattern = re.compile(
                r'href="(/web-security/[^"]+)"[^>]*>([^<]{5,80})</a>', re.I
            )
            for m in pattern.finditer(html):
                href, text = m.group(1), m.group(2)
                if query_lower in text.lower() or query_lower in href.lower():
                    results.append(
                        _result(
                            f"PS:{href}",
                            text.strip(),
                            f"PortSwigger Web Security Academy – {text.strip()}",
                            severity="EDUCATIONAL",
                            url="https://portswigger.net" + href,
                        )
                    )
                    if len(results) >= max_results:
                        break
        return results
    except Exception:
        return []


# ---------------------------------------------------------------------------
# PacketStorm Security
# ---------------------------------------------------------------------------

async def fetch_packetstorm(query: str, max_results: int = 5) -> List[Dict]:
    url = f"https://packetstormsecurity.com/search/?q={quote_plus(query)}&submit=Search"
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS,
                                     follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return []
            html = resp.text

        results: List[Dict] = []
        try:
            from bs4 import BeautifulSoup  # type: ignore
            soup = BeautifulSoup(html, "html.parser")
            for dl in soup.select("dl.file")[:max_results]:
                dt = dl.find("dt")
                dd = dl.find("dd")
                if not dt:
                    continue
                a = dt.find("a", href=True)
                if not a:
                    continue
                title = a.get_text(strip=True)
                href = a["href"]
                full_url = href if href.startswith("http") else "https://packetstormsecurity.com" + href
                desc = dd.get_text(strip=True)[:200] if dd else ""
                results.append(
                    _result(
                        f"PS:{href.split('/')[-2] if '/' in href else href}",
                        title,
                        desc,
                        url=full_url,
                    )
                )
        except ImportError:
            pattern = re.compile(
                r'href="(https://packetstormsecurity\.com/files/\d+/[^"]+)"[^>]*>([^<]{5,100})</a>',
                re.I,
            )
            for m in list(pattern.finditer(html))[:max_results]:
                href, title = m.group(1), m.group(2)
                results.append(_result(f"PSS:{href.split('/')[-2]}", title.strip(), url=href))
        return results
    except Exception:
        return []


# ---------------------------------------------------------------------------
# CTFTime Writeups
# ---------------------------------------------------------------------------

async def fetch_ctftime_writeups(query: str, max_results: int = 5) -> List[Dict]:
    url = f"https://ctftime.org/writeups?q={quote_plus(query)}"
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS,
                                     follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return []
            html = resp.text

        results: List[Dict] = []
        try:
            from bs4 import BeautifulSoup  # type: ignore
            soup = BeautifulSoup(html, "html.parser")
            for a in soup.select("a[href*='/writeup/']")[:max_results]:
                href = a["href"]
                title = a.get_text(strip=True)
                if not title:
                    continue
                full_url = href if href.startswith("http") else "https://ctftime.org" + href
                results.append(
                    _result(
                        f"CTFTime:{href.split('/')[-1]}",
                        title,
                        "CTFTime Writeup",
                        severity="CTF",
                        url=full_url,
                    )
                )
        except ImportError:
            pattern = re.compile(r'href="(/writeup/\d+)"[^>]*>([^<]{5,100})</a>', re.I)
            for m in pattern.finditer(html):
                href, title = m.group(1), m.group(2)
                results.append(
                    _result(
                        f"CTFTime:{href.split('/')[-1]}",
                        title.strip(),
                        "CTFTime Writeup",
                        severity="CTF",
                        url="https://ctftime.org" + href,
                    )
                )
                if len(results) >= max_results:
                    break
        return results
    except Exception:
        return []


# ---------------------------------------------------------------------------
# GitHub CTF Writeup Repositories
# ---------------------------------------------------------------------------

async def fetch_github_ctf(query: str, max_results: int = 5) -> List[Dict]:
    url = "https://api.github.com/search/repositories"
    params = {"q": f"ctf writeup {query}", "sort": "stars", "order": "desc",
              "per_page": min(max_results, 10)}
    gh_headers = {**HEADERS, "Accept": "application/vnd.github+json",
                  "X-GitHub-Api-Version": "2022-11-28"}
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, headers=gh_headers) as client:
            resp = await client.get(url, params=params)
            if resp.status_code != 200:
                return []
            items = resp.json().get("items", [])
            results: List[Dict] = []
            for item in items[:max_results]:
                results.append(
                    _result(
                        f"GH:{item.get('full_name', '')}",
                        item.get("full_name", ""),
                        (item.get("description") or "") + f" | ⭐ {item.get('stargazers_count', 0)}",
                        severity="CTF",
                        url=item.get("html_url", ""),
                    )
                )
            return results
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Source Registry
# ---------------------------------------------------------------------------

SOURCE_FETCHERS = {
    "nvd": fetch_nvd,
    "exploitdb": fetch_exploitdb,
    "github_advisories": fetch_github_advisories,
    "hackerone_disclosed": fetch_hackerone_disclosed,
    "gtfobins": fetch_gtfobins,
    "portswigger": fetch_portswigger,
    "packetstorm": fetch_packetstorm,
    "ctftime_writeups": fetch_ctftime_writeups,
    "github_ctf": fetch_github_ctf,
}

SOURCE_DISPLAY = {
    "nvd": "NVD",
    "exploitdb": "ExploitDB",
    "github_advisories": "GitHub Advisories",
    "hackerone_disclosed": "HackerOne",
    "gtfobins": "GTFOBins",
    "portswigger": "PortSwigger",
    "packetstorm": "PacketStorm",
    "ctftime_writeups": "CTFTime",
    "github_ctf": "GitHub CTF",
}
