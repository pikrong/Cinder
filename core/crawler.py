"""Polite same-host crawler with robots.txt enforcement and optional JS rendering."""
from __future__ import annotations

import asyncio
import json
import re
from typing import Callable
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse
from urllib.robotparser import RobotFileParser

from bs4 import BeautifulSoup

from .http_client import HttpClient

SKIP_PREFIXES = ("mailto:", "tel:", "javascript:", "data:", "#")

FORCED_PARAMS = ("id", "page", "file", "url", "search", "cmd")

RENDER_TIMEOUT_MS = 15000

JS_ENDPOINT_RE = re.compile(
    r"""["'`]((?:https?://[^"'`\s]+)|(?:/[A-Za-z0-9_\-./]*(?:api|graphql|v\d|rest)[A-Za-z0-9_\-./?=&]*))["'`]""",
    re.I,
)

JSON_ENDPOINT_KEY_RE = re.compile(r"(?:url|endpoint|href|link|api|path|uri)$", re.I)
JSON_ENDPOINT_VAL_RE = re.compile(r"^(?:https?://|/)[^\s]+$")


def _normalise(url: str) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path or "/", "", p.query, ""))


def _extract_links(html: str, base: str) -> list[str]:
    soup = BeautifulSoup(html, "lxml")
    links: list[str] = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith(SKIP_PREFIXES) or not href:
            continue
        links.append(urljoin(base, href))
    return links


def extract_forms(html: str, base: str) -> list[dict]:
    """Parse <form> elements: [{action, method, inputs:[names]}]."""
    soup = BeautifulSoup(html, "lxml")
    forms: list[dict] = []
    for form in soup.find_all("form"):
        action = urljoin(base, form.get("action") or base)
        method = (form.get("method") or "get").upper()
        inputs = [
            inp.get("name")
            for inp in form.find_all(["input", "textarea", "select"])
            if inp.get("name")
        ]
        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms


def form_test_urls(form: dict) -> list[str]:
    """Turn a form into testable URLs (GET: query params; POST: action with synthetic query)."""
    action = form["action"]
    inputs = form["inputs"] or ["q"]
    out: list[str] = []
    if form["method"] == "GET":
        parsed = urlparse(action)
        for name in inputs:
            query = dict(parse_qs(parsed.query, keep_blank_values=True))
            query[name] = ["test"]
            out.append(urlunparse(parsed._replace(query=urlencode(query, doseq=True))))
    else:
        parsed = urlparse(action)
        query = dict(parse_qs(parsed.query, keep_blank_values=True))
        for name in inputs:
            query[name] = ["test"]
        out.append(urlunparse(parsed._replace(query=urlencode(query, doseq=True))))
    return out


def json_endpoints(payload: str, base: str) -> list[str]:
    """Recursively find endpoint-like values in a JSON document."""
    try:
        data = json.loads(payload)
    except Exception:
        return []
    found: list[str] = []

    def walk(node) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, str) and JSON_ENDPOINT_KEY_RE.search(str(key)) and JSON_ENDPOINT_VAL_RE.match(value):
                    found.append(urljoin(base, value))
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    return found


class Crawler:
    def __init__(
        self,
        client: HttpClient,
        max_depth: int = 2,
        max_pages: int = 100,
        same_host_only: bool = True,
        respect_robots: bool = True,
        delay: float = 0.3,
        user_agent: str = "Cinder/1.0",
        on_page: Callable[[], None] | None = None,
    ) -> None:
        self.client = client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.same_host_only = same_host_only
        self.respect_robots = respect_robots
        self.delay = delay
        self.user_agent = user_agent
        self.on_page = on_page
        self._robots: RobotFileParser | None = None
        self._robots_host: str | None = None
        self.js_urls: list[str] = []
        self.forms: list[dict] = []
        self.xhr: list[dict] = []

    @property
    def api_targets(self) -> list[dict]:
        """Captured XHR/fetch requests as {method, url, headers, body} dicts."""
        targets: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for item in self.xhr:
            key = (item.get("method", "GET"), item.get("url", ""))
            if key in seen or not item.get("url"):
                continue
            seen.add(key)
            targets.append({
                "method": item.get("method", "GET"),
                "url": item["url"],
                "headers": item.get("headers", {}),
                "body": item.get("body", ""),
            })
        return targets

    async def _load_robots(self, start: str) -> None:
        parsed = urlparse(start)
        host = f"{parsed.scheme}://{parsed.netloc}"
        if self._robots_host == host:
            return
        self._robots_host = host
        parser = RobotFileParser()
        parser.set_url(urljoin(host, "/robots.txt"))
        if not self.respect_robots:
            parser.parse([])
            self._robots = parser
            return
        try:
            resp = await self.client.get(parser.url)
            parser.parse(resp.body.splitlines() if resp else [])
        except Exception:
            parser.parse([])
        self._robots = parser

    def _allowed(self, url: str) -> bool:
        if self._robots is None:
            return True
        return self._robots.can_fetch(self.user_agent, url)

    async def crawl(self, start: str) -> list[str]:
        await self._load_robots(start)
        host = urlparse(start).netloc
        queue: list[tuple[str, int]] = [(start, 0)]
        visited: set[str] = set()
        pages: list[str] = []

        while queue and len(pages) < self.max_pages:
            url, depth = queue.pop(0)
            norm = _normalise(url)
            if norm in visited:
                continue
            parsed = urlparse(norm)
            if parsed.scheme not in ("http", "https"):
                continue
            if self.same_host_only and parsed.netloc != host:
                continue
            visited.add(norm)
            if self.respect_robots and not self._allowed(norm):
                continue
            pages.append(norm)
            if self.on_page:
                self.on_page()
            if depth >= self.max_depth:
                continue
            if self.delay:
                await asyncio.sleep(self.delay)
            resp = await self.client.get(norm)
            if not resp:
                continue
            content_type = resp.headers.get("content-type", "").lower()
            if "json" in content_type:
                for endpoint in json_endpoints(resp.body, norm):
                    if _normalise(endpoint) not in visited:
                        queue.append((endpoint, depth + 1))
                continue
            if "html" not in content_type:
                continue
            for form in extract_forms(resp.body, norm):
                self.forms.append(form)
                for test_url in form_test_urls(form):
                    if _normalise(test_url) not in visited:
                        queue.append((test_url, depth + 1))
            for link in _extract_links(resp.body, norm):
                if _normalise(link) not in visited:
                    queue.append((link, depth + 1))

        self.visited = pages
        return pages

    async def render_js(self, start: str) -> list[str]:
        """Render pages with Playwright, harvesting DOM links and XHR/fetch URLs.

        Returns [] (and logs a warning) when Playwright is unavailable.
        """
        try:
            from playwright.async_api import async_playwright
        except Exception:
            self._warn("Playwright tidak terinstall — render JS dilewati (pakai HTTPX).")
            return []

        host = urlparse(start).netloc
        found: list[str] = []
        seen: set[str] = set()

        def _add(candidate: str | None) -> None:
            if not candidate:
                return
            url = urljoin(start, candidate)
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return
            if self.same_host_only and parsed.netloc != host:
                return
            norm = _normalise(url)
            if norm in seen:
                return
            seen.add(norm)
            found.append(norm)

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                page = await browser.new_page()

                def _harvest(request) -> None:
                    _add(request.url)
                    if request.resource_type in ("xhr", "fetch"):
                        self.xhr.append({
                            "method": request.method,
                            "url": request.url,
                            "headers": dict(request.headers),
                            "body": request.post_data or "",
                        })
                    elif request.resource_type == "script":
                        self.js_urls.append(request.url)

                page.on("request", _harvest)
                try:
                    await page.goto(start, wait_until="networkidle", timeout=RENDER_TIMEOUT_MS)
                except Exception:
                    pass
                try:
                    hrefs = await page.eval_on_selector_all(
                        "a[href]", "els => els.map(e => e.href)"
                    )
                except Exception:
                    hrefs = []
                for href in hrefs:
                    _add(href)
                try:
                    html = await page.content()
                except Exception:
                    html = ""
                for script in JS_ENDPOINT_RE.findall(html):
                    _add(script)
                await browser.close()
        except Exception as exc:
            self._warn(f"Render JS gagal ({type(exc).__name__}) — lanjut pakai HTTPX.")
            return []

        return found

    @staticmethod
    def _warn(message: str) -> None:
        import sys
        print(f"[warning] {message}", file=sys.stderr)

    async def login(
        self,
        login_url: str,
        username_field: str,
        password_field: str,
        username: str,
        password: str,
    ) -> bool:
        """POST credentials; cookies persist in the shared httpx client jar."""
        data = {username_field: username, password_field: password}
        resp = await self.client.post(login_url, data=data)
        if not resp:
            self._warn(f"Login gagal: request ke {login_url} tidak berhasil.")
            return False
        ok = resp.status < 400 and bool(resp.set_cookies)
        if not ok and resp.status < 400:
            ok = True  # server accepted but used existing/token auth
        self._warn(
            f"Login {'berhasil' if ok else 'gagal'} (status {resp.status}, "
            f"{len(resp.set_cookies)} cookie)."
        )
        return ok

    @staticmethod
    def force_params(base_url: str) -> list[str]:
        """Return `base_url` with each forced parameter appended (unique by key)."""
        parsed = urlparse(base_url)
        from urllib.parse import parse_qs, urlencode
        existing = parse_qs(parsed.query, keep_blank_values=True)
        out: list[str] = []
        for name in FORCED_PARAMS:
            if name in existing:
                continue
            query = dict(existing)
            query[name] = ["1" if name in ("id", "page") else "test"]
            out.append(urlunparse(parsed._replace(query=urlencode(query, doseq=True))))
        return out
