"""Server-side template injection detection."""
from __future__ import annotations

from typing import Callable

from core.http_client import HttpClient
from core.reporter import Finding
from . import common, evidence

PAYLOADS = ["{{7*7}}", "${7*7}", "#{7*7}", "@(7*7)", "%{7*7}"]
CONFIRM_PAYLOAD = "{{7*'7'}}"
CONFIRM_VALUE = "7777777"
RESULT_VALUE = "49"


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
        for payload in PAYLOADS
    ]
    total = len(attempts)
    hit: set[tuple[str, str]] = set()
    baselines: dict[str, bool] = {}
    for index, (page, key, payload) in enumerate(attempts):
        if progress_cb:
            progress_cb(index + 1, total)
        if page not in baselines:
            baseline = await client.get(page)
            baselines[page] = bool(baseline and RESULT_VALUE in baseline.body)
        if baselines[page] or (page, key) in hit:
            continue
        probe = common.inject(page, key, payload)
        resp = await client.get(probe)
        if not resp or RESULT_VALUE not in resp.body:
            continue
        if payload in resp.body:
            continue
        confirm_resp = await client.get(common.inject(page, key, CONFIRM_PAYLOAD))
        confirmed = bool(confirm_resp and CONFIRM_VALUE in confirm_resp.body)
        hit.add((page, key))
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
    return findings
