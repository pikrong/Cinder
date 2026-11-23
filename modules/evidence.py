"""Structured request/response evidence for findings."""
from __future__ import annotations

from datetime import datetime, timezone

from core.http_client import Response
from core.reporter import Finding

BODY_SNIPPET = 500
HEADER_LIMIT = 20


def _fmt_headers(headers: dict | None) -> str:
    if not headers:
        return ""
    return "\n".join(f"{k}: {v}" for k, v in list(headers.items())[:HEADER_LIMIT])


def capture(
    request_method: str,
    url: str,
    headers: dict | None = None,
    body: str = "",
    response_status: int = 0,
    response_headers: dict | None = None,
    response_body: str = "",
    payload: str = "",
) -> dict:
    """Capture a request/response pair into a reporter-ready dict."""
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    request = f"{request_method} {url}"
    header_text = _fmt_headers(headers)
    if header_text:
        request += "\n" + header_text
    if body:
        request += "\n\n" + body[:BODY_SNIPPET]

    response = f"HTTP {response_status}"
    resp_header_text = _fmt_headers(response_headers)
    if resp_header_text:
        response += "\n" + resp_header_text
    response += "\n\n" + response_body[:BODY_SNIPPET]

    reproduction = f"curl -sS -i -X {request_method} {url!r}"
    if payload:
        reproduction += f"  # payload: {payload!r}"

    return {
        "request": request,
        "response": response,
        "payload": payload,
        "timestamp": timestamp,
        "reproduction": reproduction,
    }


def to_finding(
    check: str,
    severity: str,
    url: str,
    detail: str,
    captured: dict,
    confidence: str = "",
) -> Finding:
    evidence_text = "\n".join(
        part for part in (
            f"payload: {captured['payload']}" if captured.get("payload") else "",
            f"time: {captured['timestamp']}",
            f"repro: {captured['reproduction']}",
        ) if part
    )
    return Finding(
        check=check,
        severity=severity,
        url=url,
        detail=detail,
        evidence=evidence_text,
        request=captured["request"],
        response=captured["response"],
        payload=captured.get("payload", ""),
        timestamp=captured.get("timestamp", ""),
        reproduction=captured.get("reproduction", ""),
        confidence=confidence,
    )


async def retest(client, normal_url: str, payload_url: str) -> bool:
    """True when the normal and payload responses are identical (weak signal).

    Sends one baseline request and one payload request, compares a hash of the
    response body. Used to downgrade confidence on sqli/xss findings.
    """
    import hashlib

    base = await client.get(normal_url)
    probe = await client.get(payload_url)
    if not base or not probe:
        return False
    base_hash = hashlib.sha256(base.body.encode("utf-8", "ignore")).hexdigest()
    probe_hash = hashlib.sha256(probe.body.encode("utf-8", "ignore")).hexdigest()
    return base_hash == probe_hash and base.status == probe.status


def from_response(
    check: str,
    severity: str,
    url: str,
    detail: str,
    resp: Response,
    payload: str = "",
    method: str = "GET",
    confidence: str = "",
) -> Finding:
    """Convenience wrapper: capture `resp` and build a Finding."""
    body = getattr(resp, "request_body", "") or ""
    captured = capture(
        method,
        url,
        headers=getattr(resp, "request_headers", None),
        body=body,
        response_status=resp.status,
        response_headers=resp.headers,
        response_body=resp.body,
        payload=payload,
    )
    return to_finding(check, severity, url, detail, captured, confidence=confidence)


def raw(
    check: str,
    severity: str,
    url: str,
    detail: str,
    request: str = "",
    response: str = "",
    payload: str = "",
) -> Finding:
    """Build a Finding from pre-formatted request/response text (no Response object)."""
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    evidence_text = "\n".join(
        part for part in (
            f"payload: {payload}" if payload else "",
            f"time: {timestamp}",
            f"repro: {request}" if request else "",
        ) if part
    )
    return Finding(
        check=check,
        severity=severity,
        url=url,
        detail=detail,
        evidence=evidence_text,
        request=request,
        response=response,
        payload=payload,
        timestamp=timestamp,
        reproduction=request,
    )
