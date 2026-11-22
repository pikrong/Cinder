"""OS command injection detection."""
from __future__ import annotations

from typing import Callable

from core.http_client import HttpClient
from core.reporter import Finding
from . import common, evidence

PARAM_HINTS = (
    "cmd", "exec", "command", "ping", "query", "run", "system",
    "shell", "process", "ip", "host", "port", "dir", "file", "path",
)

PAYLOADS = [";id", "|id", "||id", "&&id", "`id`", "$(id)", "%0aid"]

SIGNATURES = ("uid=", "root:x:")


async def run(
    client: HttpClient,
    pages: list[str],
    skip: list[str] | None = None,
    progress_cb: Callable[[int, int], None] | None = None,
) -> list[Finding]:
    skip = skip or []
    findings: list[Finding] = []
    attempts = [
        (page, key, payload)
        for page in pages
        for key in common.param_keys(page, skip)
        if common.hint(key, PARAM_HINTS)
        for payload in PAYLOADS
    ]
    total = len(attempts)
    hit: set[tuple[str, str]] = set()
    for index, (page, key, payload) in enumerate(attempts):
        if progress_cb:
            progress_cb(index + 1, total)
        if (page, key) in hit:
            continue
        probe = common.inject(page, key, payload)
        resp = await client.get(probe)
        if not resp:
            continue
        if any(signature in resp.body for signature in SIGNATURES):
            hit.add((page, key))
            findings.append(evidence.from_response(
                check="cmdi",
                severity="critical",
                url=probe,
                detail=f"Command injection via parameter '{key}'",
                resp=resp,
                payload=payload,
            ))
    return findings
