"""Unsafe deserialization indicator detection."""
from __future__ import annotations

import base64
import re

from core.http_client import HttpClient
from core.reporter import Finding
from . import evidence

B64_RE = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")

SIGNATURES = [
    ("PHP serialize", lambda raw, decoded: decoded.startswith(b"O:") or raw.startswith("O:")),
    ("Java serialized", lambda raw, decoded: decoded.startswith(b"\xac\xed") or "rO0AB" in raw),
    ("Python pickle", lambda raw, decoded: decoded[:2] in (b"\x80\x04", b"\x80\x05")),
    (".NET BinaryFormatter", lambda raw, decoded: raw.startswith("AAEAAAD")),
]


def _decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception:
        return b""


def _match(value: str) -> str | None:
    decoded = _decode(value)
    for label, check in SIGNATURES:
        try:
            if check(value, decoded):
                return label
        except Exception:
            continue
    return None


def _candidates(resp) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for name, value in resp.headers.items():
        if name.lower() == "set-cookie":
            for cookie in value.split(","):
                if "=" in cookie:
                    cname, cvalue = cookie.split("=", 1)
                    found.append((f"cookie:{cname.strip()}", cvalue.split(";")[0].strip()))
    for raw in B64_RE.findall(resp.body[:20000]):
        found.append(("body", raw))
    return found


async def run(client: HttpClient, pages: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for page in pages:
        resp = await client.get(page)
        if not resp:
            continue
        for source, value in _candidates(resp):
            label = _match(value)
            if not label:
                continue
            findings.append(evidence.from_response(
                check="deser",
                severity="high",
                url=page,
                detail=f"Indikasi data serialized tidak aman ({label}) di {source}",
                resp=resp,
                payload=value[:120],
            ))
            break
    return findings
