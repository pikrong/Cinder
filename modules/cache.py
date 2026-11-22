"""Web cache poisoning via forwarded headers."""
from __future__ import annotations

from core.http_client import HttpClient
from core.reporter import Finding
from . import evidence

POISON_HEADERS = {"X-Forwarded-Host": "evil.com", "X-Forwarded-Scheme": "nothttps"}


async def run(client: HttpClient, pages: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for page in pages:
        clean = await client.get(page)
        if not clean:
            continue
        poisoned = await client.get(page, headers=POISON_HEADERS)
        if not poisoned:
            continue
        if "evil.com" not in poisoned.body or "evil.com" in clean.body:
            continue
        confirm = await client.get(page)
        cached = bool(confirm and "evil.com" in confirm.body)
        findings.append(evidence.from_response(
            check="cache",
            severity="medium",
            url=page,
            detail="Cache poisoning: X-Forwarded-Host tercermin"
                   + (" dan tersimpan di cache" if cached else ""),
            resp=poisoned,
            payload="X-Forwarded-Host: evil.com",
        ))
    return findings
