"""
DSEC Browser Tool – Headless Playwright Integration + API-less OSINT

Enhanced browser with:
  • Custom DNS resolution (1.1.1.1 for DuckDuckGo)
  • DOM extraction and interaction (click, type, extract)
  • Screenshot capture
  • Network request interception (captures XHR/fetch/API calls)
  • JS endpoint extraction (finds API paths in scripts)
  • Arbitrary JS evaluation
  • Clean HTTP repeater (structured request/response, no curl noise)
  • API-less scraping for Twitter/X (via Nitter) and Telegram
  • DuckDuckGo search without API keys

Inspired by: Hermes-agent, Playwright
"""
import asyncio
import json
import logging
import os
import re
import time
from typing import Dict, Any, List, Optional
from urllib.parse import quote_plus

logger = logging.getLogger(__name__)

from dsec.core.registry import register

# We lazy-import playwright to avoid import errors when it's not installed
_PLAYWRIGHT_AVAILABLE = True
try:
    from playwright.async_api import async_playwright
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False


class BrowserManager:
    """Manages a headless Chromium browser with custom DNS rules."""

    def __init__(self):
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None

    async def init_browser(self):
        if not _PLAYWRIGHT_AVAILABLE:
            raise RuntimeError("Playwright not installed. Run: pip install playwright && playwright install chromium")
        if not self.playwright:
            self.playwright = await async_playwright().start()
            # Custom DNS to bypass Indonesian ISP blocks on DuckDuckGo
            args = [
                '--host-resolver-rules="MAP duckduckgo.com 1.1.1.1 , MAP *.duckduckgo.com 1.1.1.1"',
                "--disable-blink-features=AutomationControlled",
            ]
            self.browser = await self.playwright.chromium.launch(headless=True, args=args)
            self.context = await self.browser.new_context(
                user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 900},
            )
            self.page = await self.context.new_page()

    async def ensure_page(self):
        if not self.page:
            await self.init_browser()

    async def goto(self, url: str) -> str:
        await self.ensure_page()
        try:
            await self.page.goto(url, wait_until="networkidle", timeout=30000)
            return f"Navigated to {url}. Title: {await self.page.title()}"
        except Exception as e:
            return f"Failed to navigate to {url}: {e}"

    async def click(self, selector: str) -> str:
        await self.ensure_page()
        try:
            await self.page.click(selector, timeout=5000)
            return f"Clicked '{selector}'"
        except Exception as e:
            return f"Failed to click '{selector}': {e}"

    async def type_text(self, selector: str, text: str) -> str:
        await self.ensure_page()
        try:
            await self.page.fill(selector, text)
            return f"Typed into '{selector}'"
        except Exception as e:
            return f"Failed to type: {e}"

    async def extract_text(self, selector: str = "body") -> str:
        await self.ensure_page()
        try:
            text = await self.page.inner_text(selector)
            # Truncate very long text
            if len(text) > 8000:
                text = text[:8000] + "\n... [truncated]"
            return text
        except Exception as e:
            return f"Extract failed: {e}"

    async def screenshot(self, path: Optional[str] = None) -> str:
        """Take a screenshot. Returns the file path."""
        await self.ensure_page()
        if not path:
            os.makedirs(os.path.expanduser("~/.dsec/screenshots"), exist_ok=True)
            path = os.path.expanduser(f"~/.dsec/screenshots/shot_{int(time.time())}.png")
        try:
            await self.page.screenshot(path=path, full_page=False)
            return f"Screenshot saved: {path}"
        except Exception as e:
            return f"Screenshot failed: {e}"

    async def get_links(self) -> str:
        """Extract all links from the current page."""
        await self.ensure_page()
        try:
            links = await self.page.eval_on_selector_all(
                "a[href]",
                "els => els.map(e => ({text: e.innerText.trim().slice(0,80), href: e.href})).filter(l => l.text && l.href)",
            )
            if not links:
                return "No links found on page."
            lines = [f"  [{i}] {l['text'][:60]} → {l['href']}" for i, l in enumerate(links[:30])]
            return f"Links ({len(links)} total, showing top 30):\n" + "\n".join(lines)
        except Exception as e:
            return f"Failed to extract links: {e}"

    # ── Network Interception ───────────────────────────────────────────────

    async def intercept_requests(self, url: str, duration: int = 10) -> str:
        """Navigate to URL while capturing all network requests (XHR, fetch, scripts, etc.)."""
        await self.ensure_page()
        captured: List[Dict[str, str]] = []

        def _on_request(request):
            rtype = request.resource_type
            if rtype in ("xhr", "fetch", "script", "stylesheet", "document", "websocket"):
                captured.append({
                    "method": request.method,
                    "url": request.url,
                    "type": rtype,
                })

        self.page.on("request", _on_request)
        try:
            await self.page.goto(url, wait_until="networkidle", timeout=30000)
            await asyncio.sleep(min(duration, 15))
        except Exception as e:
            logger.debug(f"intercept navigation error: {e}")
        finally:
            self.page.remove_listener("request", _on_request)

        if not captured:
            return f"No network requests captured for {url}"

        # Group by type for readability
        by_type: Dict[str, List[Dict[str, str]]] = {}
        for req in captured:
            by_type.setdefault(req["type"], []).append(req)

        lines = [f"Captured {len(captured)} requests from {url}:"]
        for rtype, reqs in by_type.items():
            lines.append(f"\n  [{rtype.upper()}] ({len(reqs)} requests)")
            seen = set()
            for r in reqs:
                key = f"{r['method']} {r['url']}"
                if key not in seen:
                    seen.add(key)
                    lines.append(f"    {r['method']:6s} {r['url']}")
        return "\n".join(lines)

    # ── JS Endpoint Extraction ────────────────────────────────────────────

    async def extract_js_endpoints(self) -> str:
        """Scan all inline and external JS on the current page for API endpoints."""
        await self.ensure_page()

        js_code = """
        () => {
            const scripts = [];
            // Inline scripts
            document.querySelectorAll('script:not([src])').forEach(s => {
                if (s.textContent.length > 0) scripts.push(s.textContent);
            });
            // External script URLs
            const srcs = [];
            document.querySelectorAll('script[src]').forEach(s => srcs.push(s.src));
            return {inline: scripts, external: srcs};
        }
        """
        try:
            result = await self.page.evaluate(js_code)
        except Exception as e:
            return f"Failed to extract scripts: {e}"

        endpoint_patterns = [
            re.compile(r'["\'](/api/[^"\',;\s}{)]+)["\']'),
            re.compile(r'["\'](/v[0-9]+/[^"\',;\s}{)]+)["\']'),
            re.compile(r'["\'](/graphql[^"\',;\s}{)]*)["\']'),
            re.compile(r'fetch\s*\(\s*["\']([^"\',;\s}{)]+)["\']'),
            re.compile(r'axios\.[a-z]+\s*\(\s*["\']([^"\',;\s}{)]+)["\']'),
            re.compile(r'XMLHttpRequest[^;]*open\s*\([^,]*,\s*["\']([^"\',;\s}{)]+)["\']'),
            re.compile(r'["\']https?://[^"\',;\s}{)]+["\']'),
            re.compile(r'\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\',;\s}{)]+)["\']'),
            re.compile(r'["\'](/[a-z][a-z0-9_/\-]*(?:\.[a-z]{2,4})?)["\']'),
        ]

        endpoints: set = set()
        skip_exts = {'.js', '.css', '.png', '.jpg', '.gif', '.svg', '.woff', '.ttf', '.ico', '.map'}

        # Scan inline scripts
        for script_text in result.get("inline", []):
            for pattern in endpoint_patterns:
                for match in pattern.finditer(script_text):
                    ep = match.group(match.lastindex or 0)
                    if not any(ep.lower().endswith(ext) for ext in skip_exts):
                        endpoints.add(ep)

        # Fetch and scan external scripts
        for src_url in result.get("external", [])[:20]:
            try:
                resp = await self.page.evaluate("(url) => fetch(url).then(r => r.text())", src_url)
                if resp and len(resp) < 500000:
                    for pattern in endpoint_patterns:
                        for match in pattern.finditer(resp):
                            ep = match.group(match.lastindex or 0)
                            if not any(ep.lower().endswith(ext) for ext in skip_exts):
                                endpoints.add(ep)
            except Exception:
                continue

        if not endpoints:
            return "No API endpoints found in page JavaScript."

        # Categorize
        api_paths = sorted(ep for ep in endpoints if ep.startswith('/'))
        full_urls = sorted(ep for ep in endpoints if ep.startswith('http'))

        lines = [f"Found {len(endpoints)} potential endpoints:"]
        if api_paths:
            lines.append(f"\n  [API PATHS] ({len(api_paths)})")
            for p in api_paths[:50]:
                lines.append(f"    {p}")
        if full_urls:
            lines.append(f"\n  [FULL URLs] ({len(full_urls)})")
            for u in full_urls[:30]:
                lines.append(f"    {u}")

        lines.append(f"\n  [EXTERNAL JS FILES] ({len(result.get('external', []))})")
        for src in result.get("external", [])[:15]:
            lines.append(f"    {src}")

        return "\n".join(lines)

    # ── JS Evaluation ─────────────────────────────────────────────────────

    async def eval_js(self, code: str) -> str:
        """Execute arbitrary JavaScript on the current page and return the result."""
        await self.ensure_page()
        try:
            result = await self.page.evaluate(code)
            if result is None:
                return "[JS returned null/undefined]"
            if isinstance(result, (dict, list)):
                return json.dumps(result, indent=2, default=str)[:8000]
            return str(result)[:8000]
        except Exception as e:
            return f"JS eval error: {e}"

    # ── API-less OSINT Routines ───────────────────────────────────────────

    async def search_duckduckgo(self, query: str) -> str:
        """Search DuckDuckGo via the HTML-only endpoint (no API key needed)."""
        await self.ensure_page()
        url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
        try:
            await self.page.goto(url, wait_until="networkidle", timeout=20000)
            results = await self.page.query_selector_all(".result")
            items: list[str] = []
            for r in results[:10]:
                title_el = await r.query_selector(".result__a")
                snippet_el = await r.query_selector(".result__snippet")
                title = (await title_el.inner_text()).strip() if title_el else ""
                snippet = (await snippet_el.inner_text()).strip() if snippet_el else ""
                href = await title_el.get_attribute("href") if title_el else ""
                if title:
                    items.append(f"  [{len(items)+1}] {title}\n      {snippet}\n      {href}")
            if not items:
                return f"No DuckDuckGo results for: {query}"
            return f"DuckDuckGo results for '{query}':\n" + "\n".join(items)
        except Exception as e:
            return f"DuckDuckGo search failed: {e}"

    async def crawl_twitter(self, query: str) -> str:
        """API-less crawling of Twitter/X via Nitter instances or direct scraping."""
        await self.ensure_page()
        nitter_instances = [
            f"https://nitter.privacydev.net/search?q={quote_plus(query)}",
            f"https://nitter.poast.org/search?q={quote_plus(query)}",
        ]
        for url in nitter_instances:
            try:
                await self.page.goto(url, wait_until="networkidle", timeout=15000)
                tweets = await self.page.query_selector_all(".timeline-item")
                if tweets:
                    results = []
                    for tweet in tweets[:10]:
                        text = await tweet.inner_text()
                        results.append(text.strip().replace("\n", " ")[:300])
                    return "\n---\n".join(results)
            except Exception:
                continue
        return f"No Twitter/X results found for: {query} (all Nitter instances failed)"

    async def crawl_telegram(self, channel: str) -> str:
        """API-less crawling of public Telegram channels via t.me/s/ web interface."""
        await self.ensure_page()
        url = f"https://t.me/s/{channel}"
        try:
            await self.page.goto(url, wait_until="networkidle", timeout=15000)
            messages = await self.page.query_selector_all(".tgme_widget_message_text")
            results = []
            for msg in messages[-10:]:
                text = await msg.inner_text()
                results.append(text.strip().replace("\n", " ")[:500])
            if not results:
                return f"No messages found in public telegram channel: {channel}"
            return "\n---\n".join(results)
        except Exception as e:
            return f"Telegram crawl failed for '{channel}': {e}"


_BROWSER = BrowserManager()


def _run_async(coro):
    """Helper to run async in a sync context, handling existing event loops."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result(timeout=60)
    return asyncio.run(coro)


# ═══════════════════════════════════════════════════════════════════════════
# Registered Tools
# ═══════════════════════════════════════════════════════════════════════════

@register("browser_goto", "Navigates the headless browser to a URL and returns the page title.")
def browser_goto(url: str) -> str:
    from urllib.parse import urlparse
    from dsec.scope import validate_target
    
    parsed = urlparse(url)
    target = parsed.hostname or url
    is_allowed, reason = validate_target(target)
    if not is_allowed:
        return f"[error: execution blocked by scope enforcement: {reason}]"

    return _run_async(_BROWSER.goto(url))

@register("browser_click", "Clicks an element on the current page using a CSS selector.")
def browser_click(selector: str) -> str:
    return _run_async(_BROWSER.click(selector))

@register("browser_type", "Types text into an input field on the current page.")
def browser_type(selector: str, text: str) -> str:
    return _run_async(_BROWSER.type_text(selector, text))

@register("browser_extract", "Extracts the text content of a CSS selector from the current page.")
def browser_extract(selector: str = "body") -> str:
    return _run_async(_BROWSER.extract_text(selector))

@register("browser_screenshot", "Takes a screenshot of the current page.")
def browser_screenshot() -> str:
    return _run_async(_BROWSER.screenshot())

@register("browser_links", "Extracts all links from the current page.")
def browser_links() -> str:
    return _run_async(_BROWSER.get_links())

@register("web_search", "Searches DuckDuckGo via headless browser (no API key needed, custom DNS).")
def web_search(query: str) -> str:
    return _run_async(_BROWSER.search_duckduckgo(query))

@register("osint_crawl_twitter", "API-less search/crawl on Twitter (X) via Nitter instances.")
def osint_crawl_twitter(query: str) -> str:
    return _run_async(_BROWSER.crawl_twitter(query))

@register("osint_crawl_telegram", "API-less scrape of a public Telegram channel.")
def osint_crawl_telegram(channel: str) -> str:
    return _run_async(_BROWSER.crawl_telegram(channel))

@register("browser_intercept", "Navigate to URL and capture all network requests (XHR, fetch, API calls, scripts). Great for finding hidden endpoints.")
def browser_intercept(url: str, duration: int = 10) -> str:
    from urllib.parse import urlparse
    from dsec.scope import validate_target
    parsed = urlparse(url)
    target = parsed.hostname or url
    is_allowed, reason = validate_target(target)
    if not is_allowed:
        return f"[error: execution blocked by scope enforcement: {reason}]"
    return _run_async(_BROWSER.intercept_requests(url, duration))

@register("browser_js_endpoints", "Extract API endpoints, fetch/axios calls, and paths from all JavaScript on the current page.")
def browser_js_endpoints() -> str:
    return _run_async(_BROWSER.extract_js_endpoints())

@register("browser_eval_js", "Execute arbitrary JavaScript on the current browser page and return the result.")
def browser_eval_js(code: str) -> str:
    return _run_async(_BROWSER.eval_js(code))

@register("http_request", "Send a clean HTTP request (repeater-style). Returns status, headers, and body without curl noise.")
def http_request(url: str, method: str = "GET", headers: str = "{}", body: str = "") -> str:
    """Structured HTTP repeater — cleaner than curl for the AI."""
    from urllib.parse import urlparse
    from dsec.scope import validate_target
    import httpx

    parsed = urlparse(url)
    target = parsed.hostname or url
    is_allowed, reason = validate_target(target)
    if not is_allowed:
        return f"[error: execution blocked by scope enforcement: {reason}]"

    try:
        req_headers = json.loads(headers) if headers and headers != "{}" else {}
    except json.JSONDecodeError:
        return "[error: invalid JSON headers]"

    try:
        with httpx.Client(timeout=15, verify=False, follow_redirects=True) as client:
            resp = client.request(
                method=method.upper(),
                url=url,
                headers=req_headers,
                content=body if body else None,
            )
    except Exception as e:
        return f"[error: request failed: {e}]"

    resp_headers = "\n".join(f"  {k}: {v}" for k, v in resp.headers.items())
    resp_body = resp.text
    if len(resp_body) > 10000:
        resp_body = resp_body[:10000] + "\n... [truncated]"

    return (
        f"HTTP {resp.status_code} {resp.reason_phrase}\n"
        f"URL: {resp.url}\n"
        f"\n[Response Headers]\n{resp_headers}\n"
        f"\n[Response Body ({len(resp.text)} chars)]\n{resp_body}"
    )
