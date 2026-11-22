"""Unrestricted file upload probing."""
from __future__ import annotations

from urllib.parse import urljoin

from typing import Callable

from bs4 import BeautifulSoup

from core.http_client import HttpClient
from core.reporter import Finding
from . import evidence

FILENAMES = ["shell.php.jpg", "shell.phtml", "shell.pht", "shell.php%00.jpg", ".htaccess", "shell.svg"]
PHP_BODY = b"<?php echo 'cinder'; ?>"
SVG_BODY = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>'


def _forms(page_url: str, html: str):
    soup = BeautifulSoup(html, "lxml")
    for form in soup.find_all("form"):
        file_input = None
        for inp in form.find_all("input"):
            if (inp.get("type") or "").lower() == "file":
                file_input = inp
                break
        if not file_input:
            continue
        action = urljoin(page_url, form.get("action") or page_url)
        method = (form.get("method") or "post").upper()
        if method != "POST":
            continue
        yield action, file_input.get("name") or "file"


async def run(
    client: HttpClient,
    pages: list[str],
    progress_cb: Callable[[int, int], None] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    attempts: list[tuple[str, str, str]] = []
    for page in pages:
        resp = await client.get(page)
        if not resp:
            continue
        for action, field in _forms(page, resp.body):
            for filename in FILENAMES:
                attempts.append((action, field, filename))

    total = len(attempts)
    hit: set[tuple[str, str]] = set()
    for index, (action, field, filename) in enumerate(attempts):
        if progress_cb:
            progress_cb(index + 1, total)
        if (action, field) in hit:
            continue
        content = SVG_BODY if filename.endswith(".svg") else PHP_BODY
        uploaded = await client.post(
            action,
            files={field: (filename, content, "image/jpeg")},
            follow_redirects=False,
        )
        if not uploaded:
            continue
        location = uploaded.headers.get("location", "")
        accepted = (
            uploaded.status in (200, 201, 302)
            and (filename in uploaded.body or filename in location or b"cinder" in uploaded.body)
        )
        if not accepted:
            continue
        hit.add((action, field))
        findings.append(evidence.from_response(
            check="upload",
            severity="critical",
            url=action,
            detail=f"Upload file berbahaya diterima: {filename} (field '{field}')",
            resp=uploaded,
            payload=filename,
        ))
    return findings
