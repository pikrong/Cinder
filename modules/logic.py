"""Business-logic tampering on price/quantity/coupon parameters."""
from __future__ import annotations

from urllib.parse import urlencode

from core.http_client import HttpClient
from core.reporter import Finding
from . import common, evidence

PARAM_HINTS = ("price", "amount", "qty", "quantity", "coupon", "discount", "currency", "total")
SUCCESS_MARKERS = ("success", "order confirmed", "checkout complete", "applied", "redeemed")


def _tampered(page: str, key: str, value: str) -> str:
    probe = common.inject(page, key, value)
    if "coupon" in key.lower() or "discount" in key.lower():
        separator = "&" if "?" in probe else "?"
        probe = f"{probe}{separator}{urlencode({key: value})}"
    return probe


def _values(key: str) -> list[str]:
    low = key.lower()
    if "qty" in low or "quantity" in low:
        return ["-1", "0", "999999"]
    if "currency" in low:
        return ["IDR", "USD", "XXX"]
    if "coupon" in low or "discount" in low:
        return ["CINDER", "CINDER"]
    return ["0", "-1", "0.01"]


async def run(client: HttpClient, pages: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for page in pages:
        keys = [k for k in common.param_keys(page) if common.hint(k, PARAM_HINTS)]
        if not keys:
            continue
        baseline = await client.get(page)
        base_total = common.total(baseline.body) if baseline else None
        for key in keys:
            for value in _values(key):
                probe = _tampered(page, key, value)
                resp = await client.get(probe)
                if not resp or resp.status != 200:
                    continue
                new_total = common.total(resp.body)
                accepted = any(marker in resp.body.lower() for marker in SUCCESS_MARKERS)
                if base_total is not None and new_total is not None and new_total < base_total:
                    findings.append(evidence.from_response(
                        check="logic",
                        severity="high",
                        url=probe,
                        detail=f"Total berubah {base_total:g} → {new_total:g} via parameter '{key}'",
                        resp=resp,
                        payload=f"{key}={value}",
                    ))
                    break
                if accepted and base_total is None and common.total(resp.body) is not None:
                    findings.append(evidence.from_response(
                        check="logic",
                        severity="high",
                        url=probe,
                        detail=f"Order sukses abnormal via parameter '{key}'",
                        resp=resp,
                        payload=f"{key}={value}",
                    ))
                    break
    return findings
