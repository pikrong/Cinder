"""Security header and cookie flag checks."""
from __future__ import annotations

from urllib.parse import urlparse

from core.http_client import HttpClient, Response
from core.reporter import Finding

# (header name, label, required severity when missing)
SECURITY_HEADERS = [
    ("content-security-policy", "Content-Security-Policy", "medium"),
    ("strict-transport-security", "Strict-Transport-Security", "medium"),
    ("x-frame-options", "X-Frame-Options", "low"),
    ("x-content-type-options", "X-Content-Type-Options", "low"),
    ("referrer-policy", "Referrer-Policy", "low"),
    ("permissions-policy", "Permissions-Policy", "low"),
]


def _cookie_flags(set_cookie_values: list[str]) -> list[str]:
    issues = []
    for raw in set_cookie_values:
        name = raw.split("=", 1)[0].strip()
        parts = [p.strip().lower() for p in raw.split(";")]
        flags = {p.split("=", 1)[0] for p in parts}
        missing = []
        if "httponly" not in flags:
            missing.append("HttpOnly")
        if "secure" not in flags:
            missing.append("Secure")
        if "samesite" not in flags:
            missing.append("SameSite")
        if missing:
            issues.append(f"{name}: {', '.join(missing)}")
    return issues


async def run(client: HttpClient, url: str) -> list[Finding]:
    """Return findings for a single URL (usually the scan root)."""
    findings: list[Finding] = []
    resp: Response = await client.get(url)
    if not resp:
        return findings

    present = {k.lower(): v for k, v in resp.headers.items()}

    missing = [
        (label, sev) for key, label, sev in SECURITY_HEADERS if key not in present
    ]
    for label, sev in missing:
        findings.append(
            Finding(
                check="headers",
                severity=sev,
                url=url,
                detail=f"Header keamanan hilang: {label}",
            )
        )

    set_cookies = resp.headers.get("set-cookie")
    if set_cookies:
        cookies = [c.strip() for c in set_cookies.split(",") if c.strip()]
        for issue in _cookie_flags(cookies):
            findings.append(
                Finding(
                    check="cookies",
                    severity="high",
                    url=url,
                    detail=f"Cookie tanpa flag keamanan — {issue}",
                )
            )

    return findings
