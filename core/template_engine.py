"""Minimal Nuclei-style YAML template engine.

Template format::

    id: test-cve
    info:
      name: Example check
      severity: medium
    requests:
      - method: GET
        path: /vulnerable
        matchers:
          status: [200]
          words: ["vulnerable"]
          regex: ["v\\d+\\.\\d+"]
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path
from urllib.parse import urljoin

import yaml

from core.http_client import HttpClient
from core.reporter import Finding

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
MAX_CONCURRENCY = 20


def load_templates(directory: Path = TEMPLATE_DIR) -> list[dict]:
    templates: list[dict] = []
    if not directory.exists():
        return templates
    for path in sorted(directory.glob("*.y*ml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict) or not data.get("id") or not data.get("requests"):
            continue
        data["_source"] = path.name
        templates.append(data)
    return templates


def _match(matchers: dict, status: int, body: str) -> bool:
    if not matchers:
        return False
    if "status" in matchers and status not in matchers["status"]:
        return False
    for word in matchers.get("words", []) or []:
        if str(word) not in body:
            return False
    for pattern in matchers.get("regex", []) or []:
        if not re.search(pattern, body, re.I | re.S):
            return False
    return True


async def _fire(client: HttpClient, url: str, request: dict) -> Finding | None:
    method = request.get("method", "GET").upper()
    path = request.get("path", "/")
    payload = request.get("payload", "")
    target = urljoin(url, path)
    kwargs = {}
    if payload:
        kwargs["content"] = payload
        kwargs["headers"] = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = await client.request(method, target, **kwargs)
    if not resp:
        return None
    if not _match(request.get("matchers", {}), resp.status, resp.body):
        return None
    info = request.get("_info", {})
    return Finding(
        check=f"template:{request['_id']}",
        severity=info.get("severity", "medium"),
        url=target,
        detail=f"Template match — {info.get('name', request['_id'])}",
        request=f"{method} {target}\n{payload}",
        response=f"HTTP {resp.status}\n\n{resp.body[:400]}",
        payload=payload,
    )


async def run(
    client: HttpClient,
    pages: list[str],
    templates: list[dict] | None = None,
) -> list[Finding]:
    templates = templates if templates is not None else load_templates()
    if not templates or not pages:
        return []
    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    findings: list[Finding] = []

    async def worker(url: str, request: dict) -> None:
        async with sem:
            finding = await _fire(client, url, request)
            if finding:
                findings.append(finding)

    tasks = []
    for template in templates:
        info = template.get("info", {})
        for request in template["requests"]:
            request["_id"] = template["id"]
            request["_info"] = info
            for url in pages[:50]:
                tasks.append(worker(url, request))
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    return findings
