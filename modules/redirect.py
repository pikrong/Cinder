"""Open redirect detection on redirect-style query parameters."""
from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core.http_client import HttpClient
from core.reporter import Finding
from . import evidence

PARAM_HINTS = ("url", "redirect", "next", "return", "dest", "continue",
               "target", "redir", "callback")

PAYLOADS = ["//evil.com", "https://evil.com", "/\\evil.com", "%2f%2fevil.com"]

EVIL_HOST = "evil.com"


def _matches_hint(name: str) -> bool:
    low = name.lower()
    return any(h in low for h in PARAM_HINTS)


def _is_external(location: str) -> bool:
    host = urlparse(location).netloc.lower()
    return host == EVIL_HOST or host.endswith("." + EVIL_HOST)


def _inject(url: str, key: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    mutated = {k: v[:] for k, v in params.items()}
    mutated[key] = [payload]
    return urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))


async def run(client: HttpClient, pages: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for page in pages:
        parsed = urlparse(page)
        if not parsed.query:
            continue
        params = parse_qs(parsed.query, keep_blank_values=True)
        targets = [k for k in params if _matches_hint(k)]
        for key in targets:
            for payload in PAYLOADS:
                probe = _inject(page, key, payload)
                resp = await client.get(probe, follow_redirects=False)
                if not resp:
                    continue
                location = resp.headers.get("location", "")
                if resp.status in (301, 302, 303, 307, 308) and _is_external(location):
                    findings.append(evidence.from_response(
                        check="open_redirect",
                        severity="high",
                        url=probe,
                        detail=f"Open redirect via parameter '{key}' → {location}",
                        resp=resp,
                        payload=payload,
                    ))
                    break
    return findings
