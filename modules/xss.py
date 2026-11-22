"""Context-aware reflected XSS detection."""
from __future__ import annotations

import re
import secrets
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core.http_client import HttpClient
from core.reporter import Finding
import modules.evidence as evidence

PAYLOAD_FILE = Path(__file__).resolve().parent.parent / "payloads" / "xss.txt"

URL_ATTRS = {"href", "src", "action", "formaction", "data", "poster", "cite", "background"}
SNIPPET_LEN = 300


def _load_payloads() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    if not PAYLOAD_FILE.exists():
        return out
    for line in PAYLOAD_FILE.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        context, sep, payload = line.partition("|")
        if not sep or not payload.strip():
            continue
        out.setdefault(context.strip(), []).append(payload.lstrip())
    return out


def _inject(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    mutated = {k: v[:] for k, v in params.items()}
    mutated[key] = [value]
    return urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))


def detect_context(body: str, probe: str) -> str | None:
    """Classify where `probe` lands in the HTML: html/attr_double/attr_single/js_string/url."""
    idx = body.find(probe)
    if idx < 0:
        return None
    before = body[:idx]
    last_lt = before.rfind("<")
    last_gt = before.rfind(">")
    if last_lt > last_gt:
        seg = before[last_lt:]
        dq = seg.rfind('"')
        sq = seg.rfind("'")
        if dq == -1 and sq == -1:
            return "attr_double"
        quote_pos = max(dq, sq)
        quote = '"' if dq > sq else "'"
        attr_match = re.search(r"([\w-]+)\s*=\s*$", seg[:quote_pos])
        attr = attr_match.group(1).lower() if attr_match else ""
        if attr in URL_ATTRS:
            return "url"
        return "attr_double" if quote == '"' else "attr_single"
    lowered = before.lower()
    if lowered.rfind("<script") > lowered.rfind("</script"):
        return "js_string"
    return "html"


def _snippet(body: str, needle: str, limit: int = SNIPPET_LEN) -> str:
    idx = body.find(needle)
    if idx < 0:
        return body[:limit]
    start = max(0, idx - limit // 2)
    return body[start:start + limit]


async def run(client: HttpClient, pages: list[str], skip: list[str] | None = None) -> list[Finding]:
    skip = skip or []
    payloads = _load_payloads()
    findings: list[Finding] = []

    for page in pages:
        parsed = urlparse(page)
        if not parsed.query:
            continue
        for key in parse_qs(parsed.query, keep_blank_values=True):
            if key in skip:
                continue

            probe = "cinderXSS" + secrets.token_hex(4)
            probe_resp = await client.get(_inject(page, key, probe))
            if not probe_resp or probe not in probe_resp.body:
                continue

            context = detect_context(probe_resp.body, probe)
            if context is None:
                continue

            candidates = list(payloads.get(context, []))
            if context == "url":
                candidates += payloads.get("html", [])

            for payload in candidates:
                probe_url = _inject(page, key, payload)
                hit = await client.get(probe_url)
                if not hit or payload not in hit.body:
                    continue
                finding = evidence.from_response(
                    check="xss",
                    severity="medium",
                    url=probe_url,
                    detail=f"Reflected XSS via parameter '{key}' (context: {context})",
                    resp=hit,
                    payload=payload,
                )
                finding.evidence += (
                    f"\nparam: {key}\ncontext: {context}"
                    f"\nsnippet: {_snippet(hit.body, payload)}"
                )
                findings.append(finding)
                break

    return findings
