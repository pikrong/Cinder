"""Security header and cookie flag checks."""
from __future__ import annotations

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

CSRF_HINTS = ("xsrf", "csrf")
SESSION_HINTS = ("session", "sess", "sid", "jsessionid", "phpsessid", "auth", "login", "token")


def _is_csrf(name: str) -> bool:
    low = name.lower()
    return any(hint in low for hint in CSRF_HINTS)


def _is_session(name: str) -> bool:
    low = name.lower()
    return any(hint in low for hint in SESSION_HINTS)


def _cookie_issues(set_cookie_values: list[str]) -> list[tuple[str, str]]:
    """Return [(severity, message)] for each cookie with missing/weak flags."""
    issues: list[tuple[str, str]] = []
    for raw in set_cookie_values:
        if not raw.strip():
            continue
        name = raw.split("=", 1)[0].strip()
        flags = {p.strip().split("=", 1)[0].lower() for p in raw.split(";")}
        csrf = _is_csrf(name)
        session = _is_session(name) and not csrf

        missing = []
        if "secure" not in flags:
            missing.append("Secure")
        if "httponly" not in flags and not csrf:
            missing.append("HttpOnly")
        if "samesite" not in flags:
            missing.append("SameSite")

        if not missing:
            continue

        if session and ("Secure" in missing or "HttpOnly" in missing):
            severity = "high"
        else:
            severity = "medium"
        issues.append((severity, f"{name}: {', '.join(missing)}"))
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

    for severity, issue in _cookie_issues(resp.set_cookies):
        findings.append(
            Finding(
                check="cookies",
                severity=severity,
                url=url,
                detail=f"Cookie tanpa flag keamanan — {issue}",
            )
        )

    return findings
