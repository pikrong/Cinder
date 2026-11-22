"""Server-side template injection detection."""
from __future__ import annotations

from core.http_client import HttpClient
from core.reporter import Finding
from . import common, evidence

PAYLOADS = ["{{7*7}}", "${7*7}", "#{7*7}", "@(7*7)", "%{7*7}"]
CONFIRM_PAYLOAD = "{{7*'7'}}"
CONFIRM_VALUE = "7777777"
RESULT_VALUE = "49"


async def run(client: HttpClient, pages: list[str], skip: list[str] | None = None) -> list[Finding]:
    skip = skip or []
    findings: list[Finding] = []
    for page in pages:
        baseline = await client.get(page)
        if baseline and RESULT_VALUE in baseline.body:
            continue
        for key in common.param_keys(page, skip):
            for payload in PAYLOADS:
                probe = common.inject(page, key, payload)
                resp = await client.get(probe)
                if not resp or RESULT_VALUE not in resp.body:
                    continue
                if payload in resp.body:
                    continue
                confirm_resp = await client.get(common.inject(page, key, CONFIRM_PAYLOAD))
                confirmed = bool(confirm_resp and CONFIRM_VALUE in confirm_resp.body)
                finding = evidence.from_response(
                    check="ssti",
                    severity="high",
                    url=probe,
                    detail=f"SSTI via parameter '{key}' ({payload} → 49"
                           + (", confirmed 7*'7' → 7777777)" if confirmed else ", unconfirmed)"),
                    resp=resp,
                    payload=payload,
                )
                findings.append(finding)
                break
    return findings
