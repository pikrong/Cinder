"""Async HTTP client wrapper around httpx with retry + UA rotation."""
from __future__ import annotations

import asyncio
import random
import sys
import time
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urljoin, urlparse

import httpx

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36",
]

RETRY_STATUSES = {500, 502, 503, 504}
ROTATE_STATUSES = {403, 429}
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
MAX_BODY_BYTES = 500 * 1024
MAX_CONCURRENCY = 10
MAX_REDIRECTS = 5


@dataclass
class Response:
    url: str
    status: int
    headers: dict
    body: str
    elapsed: float
    ok: bool = True
    request_headers: dict = field(default_factory=dict)
    truncated: bool = False
    set_cookies: list = field(default_factory=list)
    request_body: str = ""

    def __bool__(self) -> bool:
        return self.ok


class HttpClient:
    """Thin async wrapper: retries 5xx up to `retries` times, rotates UA."""

    def __init__(
        self,
        timeout: float = 10.0,
        verify: bool = True,
        follow_redirects: bool = True,
        retries: int = 2,
        headers: dict | None = None,
        verbose: bool = False,
        log_sink: Callable[[str], None] | None = None,
        max_concurrency: int = MAX_CONCURRENCY,
        proxies: list[str] | None = None,
        stealth: bool = False,
    ) -> None:
        self.timeout = timeout
        self.retries = retries
        self.base_headers = headers or {}
        self.verbose = verbose
        self.log_sink = log_sink
        self.follow_redirects = follow_redirects
        self.verify = verify
        self.stealth = stealth
        self.proxies = proxies or []
        self._proxy_index = 0
        self._proxy_clients: dict[str | None, httpx.AsyncClient] = {}
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self.client = httpx.AsyncClient(
            timeout=timeout,
            verify=verify,
            follow_redirects=False,
        )
        self._proxy_clients[None] = self.client

    def _client_for(self, proxy: str | None) -> httpx.AsyncClient:
        if proxy is None:
            return self.client
        if proxy not in self._proxy_clients:
            self._proxy_clients[proxy] = httpx.AsyncClient(
                timeout=self.timeout,
                verify=self.verify,
                follow_redirects=False,
                proxy=proxy,
            )
        return self._proxy_clients[proxy]

    def _current_proxy(self) -> str | None:
        return self.proxies[self._proxy_index] if self.proxies else None

    def _rotate_proxy(self) -> None:
        if not self.proxies:
            return
        self._proxy_index = (self._proxy_index + 1) % len(self.proxies)
        self._log(f"proxy rotate → {self.proxies[self._proxy_index]}")

    async def _polite_delay(self) -> None:
        if self.stealth:
            await asyncio.sleep(random.uniform(1.0, 5.0))

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def close(self) -> None:
        for client in self._proxy_clients.values():
            await client.aclose()
        self._proxy_clients.clear()

    def _headers(self, extra: dict | None) -> dict:
        headers = dict(self.base_headers)
        headers.setdefault("User-Agent", random.choice(USER_AGENTS))
        if extra:
            headers.update(extra)
        return headers

    def _log(self, message: str) -> None:
        if not self.verbose:
            return
        if self.log_sink:
            self.log_sink(f"[dim]{message}[/]")
        else:
            print(f"[VERBOSE] {message}", file=sys.stderr)

    async def _fetch_once(self, method: str, url: str, headers: dict, client=None, **kwargs) -> Response:
        start = time.perf_counter()
        client = client or self.client
        async with client.stream(
            method, url, headers=headers, timeout=self.timeout, **kwargs
        ) as resp:
            chunks: list[bytes] = []
            size = 0
            truncated = False
            async for chunk in resp.aiter_bytes():
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_BODY_BYTES:
                    truncated = True
                    break
            raw = b"".join(chunks)[:MAX_BODY_BYTES]
            elapsed = time.perf_counter() - start
            body = raw.decode(resp.encoding or "utf-8", "replace")
            return Response(
                url=str(resp.url),
                status=resp.status_code,
                headers=dict(resp.headers),
                body=body,
                elapsed=elapsed,
                request_headers=headers,
                truncated=truncated,
                set_cookies=resp.headers.get_list("set-cookie"),
            )

    async def _request(self, method: str, url: str, **kwargs) -> Response:
        headers = self._headers(kwargs.pop("headers", None))
        follow = kwargs.pop("follow_redirects", self.follow_redirects)
        raw_body = _body_repr(kwargs)
        last = Response(url, 0, {}, "", 0.0, ok=False, request_headers=headers, request_body=raw_body)
        attempts = self.retries + 1

        async with self._semaphore:
            for attempt in range(attempts):
                await self._polite_delay()
                current = url
                try:
                    for _ in range(MAX_REDIRECTS + 1):
                        result = await self._fetch_once(
                            method, current, headers, client=self._client_for(self._current_proxy()), **kwargs
                        )
                        result.request_body = raw_body
                        location = result.headers.get("location") or result.headers.get("Location")
                        if not (follow and result.status in REDIRECT_STATUSES and location):
                            break
                        target = urljoin(current, location)
                        if urlparse(target).netloc != urlparse(url).netloc:
                            break
                        current = target
                except httpx.HTTPError as exc:
                    self._log(f"{method} {url} → ERROR ({type(exc).__name__})")
                    last = Response(url, 0, {}, str(exc), 0.0, ok=False,
                                    request_headers=headers, request_body=raw_body)
                    if self.proxies:
                        self._rotate_proxy()
                        continue
                    continue
                if result.status in ROTATE_STATUSES and self.proxies:
                    self._log(f"{method} {result.url} → {result.status} (rotate proxy)")
                    self._rotate_proxy()
                    last = result
                    continue
                self._log(
                    f"{method} {result.url} → {result.status} ({result.elapsed * 1000:.0f}ms)"
                    + (" [truncated]" if result.truncated else "")
                )
                if result.status in RETRY_STATUSES and attempt < attempts - 1:
                    last = result
                    continue
                return result
        return last

    async def get(self, url: str, **kwargs) -> Response:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Response:
        return await self._request("POST", url, **kwargs)

    async def request(self, method: str, url: str, **kwargs) -> Response:
        """Generic request: any HTTP method (GET/POST/PUT/PATCH/DELETE/...).

        Accepts the same kwargs as httpx (data=, json=, content=, files=, headers=).
        """
        return await self._request(method.upper(), url, **kwargs)


def _body_repr(kwargs: dict) -> str:
    """Best-effort textual representation of an outgoing request body."""
    if "json" in kwargs and kwargs["json"] is not None:
        try:
            import json as _json
            return _json.dumps(kwargs["json"])[:2000]
        except Exception:
            return str(kwargs["json"])[:2000]
    if "data" in kwargs and kwargs["data"] is not None:
        data = kwargs["data"]
        if isinstance(data, dict):
            from urllib.parse import urlencode
            return urlencode(data, doseq=True)[:2000]
        return str(data)[:2000]
    if "content" in kwargs and kwargs["content"] is not None:
        content = kwargs["content"]
        return content.decode("utf-8", "replace")[:2000] if isinstance(content, bytes) else str(content)[:2000]
    if "files" in kwargs and kwargs["files"]:
        return f"[multipart files: {', '.join(kwargs['files'].keys())}]"
    return ""
