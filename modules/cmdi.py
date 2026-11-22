"""OS command injection detection."""
from __future__ import annotations

from core.http_client import HttpClient
from core.reporter import Finding
from . import common, evidence

PARAM_HINTS = (
    "cmd", "exec", "command", "ping", "query", "run", "system",
    "shell", "process", "ip", "host", "port", "dir", "file", "path",
)

PAYLOADS = [";id", "|id", "||id", "&&id", "`id`", "$(id)", "%0aid"]

SIGNATURES = ("uid=", "root:x:")


async def run(client: HttpClient, pages: list[str], skip: list[str] | None = None) -> list[Finding]:
    skip = skip or []
    findings: list[Finding] = []
    for page in pages:
        for key in common.param_keys(page, skip):
            if not common.hint(key, PARAM_HINTS):
                continue
            for payload in PAYLOADS:
                probe = common.inject(page, key, payload)
                resp = await client.get(probe)
                if not resp:
                    continue
                if any(signature in resp.body for signature in SIGNATURES):
                    findings.append(evidence.from_response(
                        check="cmdi",
                        severity="critical",
                        url=probe,
                        detail=f"Command injection via parameter '{key}'",
                        resp=resp,
                        payload=payload,
                    ))
                    break
    return findings
