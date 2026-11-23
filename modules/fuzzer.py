"""Blind payload fuzzing across all parameters."""
from __future__ import annotations

from pathlib import Path

from core.http_client import HttpClient
from core.reporter import Finding
from . import common, evidence

PAYLOAD_DIR = Path(__file__).resolve().parent.parent / "payloads"


def _load() -> list[str]:
    payloads: list[str] = []
    for path in sorted(PAYLOAD_DIR.glob("*.txt")):
        for line in path.read_text(errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            payloads.append(line.rsplit("|", 1)[1].strip() if " | " in line else line)
    seen: set[str] = set()
    unique = []
    for payload in payloads:
        if payload not in seen:
            seen.add(payload)
            unique.append(payload)
    return unique


async def run(client: HttpClient, pages: list[str], max_payloads: int = 60) -> list[Finding]:
    payloads = _load()[:max_payloads]
    findings: list[Finding] = []
    for page in pages:
        keys = common.param_keys(page)
        if not keys:
            continue
        baseline = await client.get(page)
        for key in keys:
            for payload in payloads:
                probe = common.inject(page, key, payload)
                resp = await client.get(probe)
                if not resp:
                    continue
                reflected = payload in resp.body
                length_delta = abs(len(resp.body) - len(baseline.body)) if baseline else 0
                status_diff = bool(baseline and resp.status != baseline.status)
                if not (reflected or length_delta > 300 or status_diff):
                    continue
                findings.append(evidence.from_response(
                    check="fuzz",
                    severity="info",
                    url=probe,
                    detail=f"Respons berbeda untuk payload {payload!r} (param '{key}')",
                    resp=resp,
                    payload=payload,
                ))
                break
    return findings
