"""Context-aware reflected XSS detection."""
from __future__ import annotations

import re
import secrets
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core.http_client import HttpClient
from core.reporter import Finding
import modules.evidence as evidence
from . import common

PAYLOAD_FILE = Path(__file__).resolve().parent.parent / "payloads" / "xss.txt"

JSON_PAYLOAD = "<svg/onload=alert(1)>"

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


async def _json_scan(client, api_targets, findings) -> None:
    """Inject an XSS payload into JSON body values and check for reflection."""
    for target in api_targets:
        data = common.parse_json(target.get("body") or "")
        if data is None:
            continue
        url = target["url"]
        method = target.get("method", "POST")
        headers = {"Content-Type": "application/json"}
        for path, _value in common.json_scalar_paths(data):
            if not path:
                continue
            mutated = common.json_set(common.parse_json(target["body"]), path, JSON_PAYLOAD)
            resp = await client.request(method, url, json=mutated, headers=headers)
            if not resp or JSON_PAYLOAD not in resp.body:
                continue
            findings.append(evidence.from_response(
                check="xss",
                severity="medium",
                url=url,
                detail=f"JSON body XSS via '{path}' — {method} {url}",
                resp=resp,
                payload=JSON_PAYLOAD,
                method=method,
                confidence="medium",
            ))
            break


async def run(
    client: HttpClient,
    pages: list[str],
    skip: list[str] | None = None,
    progress_cb: Callable[[int, int], None] | None = None,
    api_targets: list[dict] | None = None,
) -> list[Finding]:
    skip = skip or []
    payloads = _load_payloads()
    findings: list[Finding] = []

    candidates: list[tuple[str, str, str, str]] = []
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
            pool = list(payloads.get(context, []))
            if context == "url":
                pool += payloads.get("html", [])
            for payload in pool:
                candidates.append((page, key, context, payload))

    total = len(candidates)
    hit: set[tuple[str, str]] = set()
    for index, (page, key, context, payload) in enumerate(candidates):
        if progress_cb:
            progress_cb(index + 1, total)
        if (page, key) in hit:
            continue
        probe_url = _inject(page, key, payload)
        resp = await client.get(probe_url)
        if not resp or payload not in resp.body:
            continue
        hit.add((page, key))
        confidence = "high"
        if await evidence.retest(client, page, probe_url):
            confidence = "low"
        finding = evidence.from_response(
            check="xss",
            severity="medium",
            url=probe_url,
            detail=f"Reflected XSS via parameter '{key}' (context: {context})"
                   + (" [retest: respons identik dengan baseline]" if confidence == "low" else ""),
            resp=resp,
            payload=payload,
            confidence=confidence,
        )
        finding.evidence += (
            f"\nparam: {key}\ncontext: {context}"
            f"\nsnippet: {_snippet(resp.body, payload)}"
        )
        findings.append(finding)

    if api_targets:
        await _json_scan(client, api_targets, findings)

    return findings
