"""Polite same-host crawler with robots.txt enforcement and optional JS rendering."""
from __future__ import annotations

import re
import time
from typing import Callable
from urllib.parse import urljoin, urlparse, urlunparse
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
                time.sleep(self.delay)
            resp = await self.client.get(norm)
            if not resp or "html" not in resp.headers.get("content-type", "").lower():
                continue
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
                    if request.resource_type in ("xhr", "fetch", "script"):
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
