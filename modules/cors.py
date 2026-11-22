"""CORS misconfiguration detection."""
from __future__ import annotations

from core.http_client import HttpClient
from core.reporter import Finding
from . import evidence

EVIL_ORIGIN = "https://evil.com"


async def run(client: HttpClient, pages: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for page in pages:
        resp = await client.get(page, headers={"Origin": EVIL_ORIGIN})
        if not resp:
            continue
        headers = {k.lower(): v for k, v in resp.headers.items()}
        allow_origin = headers.get("access-control-allow-origin", "")
        allow_creds = headers.get("access-control-allow-credentials", "").lower() == "true"

        if allow_origin == EVIL_ORIGIN:
            findings.append(evidence.from_response(
                check="cors",
                severity="medium",
                url=page,
                detail="CORS memantulkan Origin evil.com"
                       + (" + credentials" if allow_creds else ""),
                resp=resp,
                payload=f"Origin: {EVIL_ORIGIN}",
            ))
        elif allow_origin == "*" and allow_creds:
            findings.append(evidence.from_response(
                check="cors",
                severity="medium",
                url=page,
                detail="CORS wildcard (*) dengan credentials",
                resp=resp,
                payload=f"Origin: {EVIL_ORIGIN}",
            ))
    return findings
