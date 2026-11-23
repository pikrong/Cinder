"""Polite same-host crawler with robots.txt enforcement."""
from __future__ import annotations

import time
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.robotparser import RobotFileParser

from bs4 import BeautifulSoup

from .http_client import HttpClient

SKIP_PREFIXES = ("mailto:", "tel:", "javascript:", "data:", "#")


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
    ) -> None:
        self.client = client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.same_host_only = same_host_only
        self.respect_robots = respect_robots
        self.delay = delay
        self.user_agent = user_agent
        self._robots: RobotFileParser | None = None
        self._robots_host: str | None = None

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
