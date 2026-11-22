"""Async HTTP client wrapper around httpx with retry + UA rotation."""
from __future__ import annotations

import random
import sys
import time
from dataclasses import dataclass, field
from typing import Callable

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


@dataclass
class Response:
    url: str
    status: int
    headers: dict
    body: str
    elapsed: float
    ok: bool = True
    request_headers: dict = field(default_factory=dict)

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
    ) -> None:
        self.timeout = timeout
        self.retries = retries
        self.base_headers = headers or {}
        self.verbose = verbose
        self.log_sink = log_sink
        self.client = httpx.AsyncClient(
            timeout=timeout,
            verify=verify,
            follow_redirects=follow_redirects,
        )

    async def __aenter__(self) -> "HttpClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def close(self) -> None:
        await self.client.aclose()

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

    async def _request(self, method: str, url: str, **kwargs) -> Response:
        headers = self._headers(kwargs.pop("headers", None))
        last = Response(url, 0, {}, "", 0.0, ok=False, request_headers=headers)
        attempts = self.retries + 1
        for attempt in range(attempts):
            start = time.perf_counter()
            try:
                resp = await self.client.request(
                    method, url, headers=headers, timeout=self.timeout, **kwargs
                )
            except httpx.HTTPError as exc:
                elapsed = time.perf_counter() - start
                self._log(f"{method} {url} → ERROR ({type(exc).__name__}) ({elapsed * 1000:.0f}ms)")
                last = Response(url, 0, {}, str(exc), elapsed, ok=False, request_headers=headers)
                continue
            elapsed = time.perf_counter() - start
            self._log(f"{method} {url} → {resp.status_code} ({elapsed * 1000:.0f}ms)")
            result = Response(
                url=str(resp.url),
                status=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text,
                elapsed=elapsed,
                request_headers=headers,
            )
            if resp.status_code in RETRY_STATUSES and attempt < attempts - 1:
                last = result
                continue
            return result
        return last

    async def get(self, url: str, **kwargs) -> Response:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Response:
        return await self._request("POST", url, **kwargs)
