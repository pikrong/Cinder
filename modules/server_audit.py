"""Nikto-style server misconfiguration and file-leak probes."""
from __future__ import annotations

from urllib.parse import urljoin

from core.http_client import HttpClient
from core.reporter import Finding
from . import common, evidence

# path -> (severity, keyword that must appear in body for a positive hit)
SENSITIVE_PATHS = {
    "/server-status": ("medium", "Apache Server Status"),
    "/phpinfo.php": ("high", "phpinfo"),
    "/.htaccess": ("medium", "RewriteEngine"),
    "/web.config": ("medium", "<configuration"),
    "/crossdomain.xml": ("low", "<cross-domain-policy"),
    "/cgi-bin/": ("low", "cgi-bin"),
    "/console": ("high", "console"),
    "/actuator/env": ("high", "activeProfiles"),
}
BACKUP_PATHS = {
    "/index.php.bak": "medium",
    "/config.js.map": "medium",
    "/.DS_Store": "low",
}


async def run(client: HttpClient, base_url: str) -> list[Finding]:
    findings: list[Finding] = []
    root = common.origin(base_url)

    for path, (severity, keyword) in SENSITIVE_PATHS.items():
        url = urljoin(root + "/", path.lstrip("/"))
        resp = await client.get(url)
        if not resp or resp.status != 200:
            continue
        if keyword.lower() not in resp.body.lower():
            continue
        findings.append(evidence.from_response(
            check="server_audit",
            severity=severity,
            url=url,
            detail=f"Path server sensitif terekspos: {path}",
            resp=resp,
        ))

    for path, severity in BACKUP_PATHS.items():
        url = urljoin(root + "/", path.lstrip("/"))
        resp = await client.get(url)
        if not resp or resp.status != 200 or not resp.body.strip():
            continue
        findings.append(evidence.from_response(
            check="server_audit",
            severity=severity,
            url=url,
            detail=f"File backup/source terekspos: {path}",
            resp=resp,
        ))

    return findings
