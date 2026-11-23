"""JavaScript bundle reconnaissance."""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin

from core.http_client import HttpClient
from core.reporter import Finding
from . import evidence

ENDPOINT_RE = re.compile(
    r"""["'`](/(?:api|v\d|graphql|admin|user|account|auth|internal)[A-Za-z0-9_\-/.]*)["'`]"""
)
SECRET_RE = re.compile(
    r"""(?:api[_-]?key|apikey|secret|token|password|passwd|access[_-]?key)["']?\s*[:=]\s*["']([A-Za-z0-9_\-./+=]{8,})["']""",
    re.I,
)
SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)


def _scan(text: str, endpoints: set[str], findings: list[Finding], js_url: str) -> None:
    for endpoint in ENDPOINT_RE.findall(text):
        endpoints.add(endpoint)
    for secret in SECRET_RE.findall(text):
        findings.append(evidence.raw(
            check="jsrecon",
            severity="medium",
            url=js_url,
            detail=f"Kemungkinan secret hardcoded: {secret[:4]}...{secret[-4:]}",
            request=f"GET {js_url}",
            response=secret[:120],
            payload="",
        ))


async def run(client: HttpClient, pages: list[str]) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    endpoints: set[str] = set()
    seen: set[str] = set()

    for page in pages[:20]:
        resp = await client.get(page)
        if not resp:
            continue
        for src in SRC_RE.findall(resp.body)[:20]:
            js_url = urljoin(page, src)
            if js_url in seen or not js_url.startswith("http"):
                continue
            seen.add(js_url)
            js = await client.get(js_url)
            if not js:
                continue
            _scan(js.body, endpoints, findings, js_url)
            if not js_url.endswith(".js"):
                continue
            source_map = await client.get(js_url + ".map")
            if not source_map or source_map.status != 200:
                continue
            try:
                data = json.loads(source_map.body)
            except Exception:
                continue
            if not isinstance(data, dict) or not data.get("sourcesContent"):
                continue
            for content in data["sourcesContent"]:
                if content:
                    _scan(content, endpoints, findings, js_url + ".map")
            findings.append(evidence.from_response(
                check="jsrecon",
                severity="medium",
                url=js_url + ".map",
                detail="Source map terekspos",
                resp=source_map,
            ))
    return findings, sorted(endpoints)
