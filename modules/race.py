"""Race-condition probing on sensitive endpoints."""
from __future__ import annotations

import asyncio
from urllib.parse import urlparse

from core.http_client import HttpClient
from core.reporter import Finding
from . import evidence

HINTS = ("coupon", "redeem", "balance", "transfer", "signup", "register", "inventory", "order", "checkout", "withdraw")
SUCCESS_MARKERS = ("success", "applied", "redeemed", "confirmed", "created", "completed", "credited")
CONCURRENCY = 10


def _candidates(pages: list[str]):
    for page in pages:
        blob = (urlparse(page).path + "?" + urlparse(page).query).lower()
        if any(hint in blob for hint in HINTS):
            yield page


async def run(client: HttpClient, pages: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    targets = list(_candidates(pages))
    if not targets:
        return findings

    try:
        import h2  # noqa: F401
        have_h2 = True
    except Exception:
        have_h2 = False

    for target in targets[:5]:
        if have_h2:
            import httpx
            connector_client = httpx.AsyncClient(http2=True, timeout=client.timeout)
            try:
                async def hit() -> tuple[int, str]:
                    try:
                        resp = await connector_client.get(target, headers=client.base_headers)
                        return resp.status_code, resp.text
                    except Exception:
                        return 0, ""
                results = await asyncio.gather(*[hit() for _ in range(CONCURRENCY)])
            finally:
                await connector_client.aclose()
        else:
            async def hit() -> tuple[int, str]:
                resp = await client.get(target)
                return (resp.status, resp.body) if resp else (0, "")
            results = await asyncio.gather(*[hit() for _ in range(CONCURRENCY)])

        successes = [
            (status, body) for status, body in results
            if status in (200, 201, 302) and any(m in body.lower() for m in SUCCESS_MARKERS)
        ]
        if len(successes) > 1:
            status, body = successes[0]
            findings.append(evidence.raw(
                check="race",
                severity="high",
                url=target,
                detail=f"{len(successes)} respons sukses dari {CONCURRENCY} request paralel"
                       + ("" if have_h2 else " (HTTP/1.1 fallback)"),
                request=f"GET {target} x{CONCURRENCY}",
                response=body[:500],
                payload="",
            ))
    return findings
