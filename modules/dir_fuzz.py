"""Directory bruteforce: discover hidden paths and feed them to the scanner."""
from __future__ import annotations

from pathlib import Path
from typing import Callable
from urllib.parse import urljoin

from core.http_client import HttpClient
from core.reporter import Finding
from . import common, evidence

DIR_FILE = Path(__file__).resolve().parent.parent / "payloads" / "dirs.txt"
HIT_STATUSES = {200, 301, 302, 403}


def _load() -> list[str]:
    if not DIR_FILE.exists():
        return []
    return [
        line.strip().lstrip("/")
        for line in DIR_FILE.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


async def run(
    client: HttpClient,
    base_url: str,
    progress_cb: Callable[[int, int], None] | None = None,
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    discovered: list[str] = []
    root = common.origin(base_url)
    paths = _load()
    total = len(paths)

    for index, path in enumerate(paths):
        if progress_cb:
            progress_cb(index + 1, total)
        url = urljoin(root + "/", path)
        resp = await client.get(url, follow_redirects=False)
        if not resp or resp.status not in HIT_STATUSES:
            continue
        discovered.append(url)
        severity = "medium" if resp.status in (200, 403) else "low"
        findings.append(evidence.from_response(
            check="dir_fuzz",
            severity=severity,
            url=url,
            detail=f"Path ditemukan: /{path} (status {resp.status})",
            resp=resp,
        ))
        for forced in (common.inject(url, "id", "1"),):
            discovered.append(forced)

    return findings, discovered
