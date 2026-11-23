"""Exposed sensitive file detection with signature matching."""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

from core.http_client import HttpClient
from core.reporter import Finding

PAYLOAD_FILE = Path(__file__).resolve().parent.parent / "payloads" / "files.txt"

# path -> (severity, signature regex, plain-text signature fallback)
# A path without a signature entry is only reported when no generic 404 page matches.
SIGNATURES: dict[str, tuple[str, re.Pattern | None]] = {
    ".env": ("critical", re.compile(r"(DB_PASSWORD|DB_HOST|APP_KEY|SECRET_KEY)\s*=")),
    ".git/HEAD": ("critical", re.compile(r"ref:\s+refs/")),
    ".git/config": ("critical", re.compile(r"\[core\]|\[remote")),
    ".svn/entries": ("high", re.compile(r"\bdir\b|\d+\s*\n\s*svn://")),
    "backup.zip": ("high", re.compile(r"^PK\x03\x04")),
    "config.php.bak": ("high", re.compile(r"<\?php|DB_PASSWORD|password", re.I)),
    "wp-config.php.bak": ("high", re.compile(r"DB_PASSWORD|DB_NAME|wp-config", re.I)),
    ".DS_Store": ("low", re.compile(r"Bud1")),
    "composer.json": ("medium", re.compile(r"\"(require|autoload|name)\"")),
    "package.json": ("low", re.compile(r"\"(dependencies|name|version)\"")),
}

# Generic signatures of a soft-404 / error page (skip false positives).
SOFT_404_PATTERNS = [
    re.compile(r"<title>\s*(404|not found|error)", re.I),
    re.compile(r"page (not found|does not exist)", re.I),
]


def _load_paths() -> list[str]:
    if not PAYLOAD_FILE.exists():
        return list(SIGNATURES)
    return [line.strip() for line in PAYLOAD_FILE.read_text().splitlines()
            if line.strip() and not line.startswith("#")]


def _looks_like_soft_404(body: str) -> bool:
    return any(p.search(body) for p in SOFT_404_PATTERNS)


async def run(client: HttpClient, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(base_url)
    root = f"{parsed.scheme}://{parsed.netloc}/"

    # Baseline: how does this server respond to a clearly-missing path?
    baseline = await client.get(urljoin(root, "cinder-nonexistent-probe-xyz"))
    base_len = len(baseline.body) if baseline else 0

    for path in _load_paths():
        target = urljoin(root, path)
        resp = await client.get(target)
        if not resp or resp.status != 200:
            continue

        body = resp.body
        severity, signature = SIGNATURES.get(path, ("medium", None))

        if signature is not None:
            if not signature.search(body):
                continue
        else:
            # Without a content signature, reject soft-404 pages.
            if _looks_like_soft_404(body):
                continue
            if base_len and abs(len(body) - base_len) < 20:
                continue

        if _looks_like_soft_404(body) and not (signature and signature.search(body)):
            continue

        findings.append(
            Finding(
                check="sensitive_files",
                severity=severity,
                url=target,
                detail=f"File sensitif terekspos: /{path} (HTTP 200, signature cocok)",
                evidence=body[:200],
            )
        )
    return findings
