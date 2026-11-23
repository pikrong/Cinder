"""Authentication flow weaknesses."""
from __future__ import annotations

import base64
import re
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from core.http_client import HttpClient
from core.reporter import Finding
from . import common, evidence

LOGIN_PATHS = ("/login", "/signin", "/admin/login", "/wp-login.php")
RESET_PATHS = ("/forgot-password", "/password-reset", "/reset", "/account/forgot", "/users/password/new")
OAUTH_HINTS = ("redirect_uri=", "response_type=", "client_id=")
MFA_HINTS = ("otp", "mfa", "totp", "verification_code", "code")
SUCCESS_MARKERS = ("success", "welcome", "verified", "dashboard", "logged in")
EMAIL = "cinder-probe@example.com"
OTHER_EMAIL = "admin@example.com"


def _extract_token(resp) -> str | None:
    if not resp:
        return None
    match = re.search(r"(?:token|code|reset)[=\"']{0,3}([A-Za-z0-9_\-]{6,})", resp.body, re.I)
    return match.group(1) if match else None


def _weak_token(token: str) -> bool:
    return len(token) < 8 or token.isdigit() or token.isalpha() or len(set(token)) <= 3


def _sid(set_cookie: str) -> str | None:
    match = re.search(r"(?:session|sess|sid|jsessionid)=([^;]+)", set_cookie, re.I)
    return match.group(1) if match else None


def _success(body: str) -> bool:
    low = body.lower()
    return any(marker in low for marker in SUCCESS_MARKERS)


def _decode_b64(value: str) -> bytes:
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4))
    except Exception:
        return b""


def _form_fields(form) -> dict[str, str]:
    return {
        inp.get("name"): inp.get("type") or "text"
        for inp in form.find_all("input")
        if inp.get("name")
    }


async def run(client: HttpClient, pages: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    root = common.origin(pages[0]) if pages else ""
    targets: list[str] = []
    for url in list(pages) + [root + path for path in LOGIN_PATHS + RESET_PATHS]:
        if url not in targets:
            targets.append(url)

    login_form = None
    reset_form = None
    oauth_links: list[str] = []
    mfa_forms: list[tuple[str, str]] = []

    for url in targets[:40]:
        resp = await client.get(url)
        if not resp or resp.status >= 400:
            continue
        soup = BeautifulSoup(resp.body, "lxml")
        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action") or url)
            fields = _form_fields(form)
            names = [name.lower() for name in fields]
            if any("password" in name for name in names):
                if "reset" in (url + action).lower() or "forgot" in (url + action).lower():
                    reset_form = reset_form or (action, fields)
                else:
                    login_form = login_form or (action, fields)
            code_field = next((n for n in fields if common.hint(n, MFA_HINTS)), None)
            if code_field:
                mfa_forms.append((action, code_field))
        for anchor in soup.find_all("a", href=True):
            if any(hint in anchor["href"] for hint in OAUTH_HINTS):
                oauth_links.append(urljoin(url, anchor["href"]))

    if reset_form:
        action, fields = reset_form
        email_field = next((n for n in fields if "email" in n.lower() or "user" in n.lower()), None)
        if email_field:
            first = await client.post(action, data={email_field: EMAIL})
            second = await client.post(action, data={email_field: OTHER_EMAIL})
            if first and second:
                if abs(len(first.body) - len(second.body)) > 50 or first.status != second.status:
                    findings.append(evidence.from_response(
                        check="auth",
                        severity="medium",
                        url=action,
                        detail="User enumeration pada password reset (respons berbeda)",
                        resp=second,
                        payload=f"{email_field}={OTHER_EMAIL}",
                    ))
            injected = await client.post(action, data={email_field: EMAIL}, headers={"Host": "evil.com"})
            if injected and "evil.com" in injected.body:
                findings.append(evidence.from_response(
                    check="auth",
                    severity="high",
                    url=action,
                    detail="Host header injection pada reset link",
                    resp=injected,
                    payload="Host: evil.com",
                ))
            token = _extract_token(first)
            if token and _weak_token(token):
                findings.append(evidence.from_response(
                    check="auth",
                    severity="high",
                    url=action,
                    detail=f"Reset token lemah/predictable: {token}",
                    resp=first,
                    payload=f"{email_field}={EMAIL}",
                ))

    if login_form:
        action, _ = login_form
        first = await client.get(action)
        second = await client.get(action)
        cookie1 = first.headers.get("set-cookie", "") if first else ""
        cookie2 = second.headers.get("set-cookie", "") if second else ""
        sid1, sid2 = _sid(cookie1), _sid(cookie2)
        if sid1 and sid2 and sid1 == sid2:
            findings.append(evidence.from_response(
                check="auth",
                severity="medium",
                url=action,
                detail="Session ID tidak berubah antar-request (session fixation)",
                resp=second,
            ))
        for cookie in f"{cookie1},{cookie2}".split(","):
            name, _, value = cookie.partition("=")
            if "remember" not in name.lower() and "persistent" not in name.lower():
                continue
            decoded = _decode_b64(value.split(";")[0].strip())
            if decoded and (b"password" in decoded.lower() or b":" in decoded):
                findings.append(evidence.from_response(
                    check="auth",
                    severity="high",
                    url=action,
                    detail=f"Remember-me cookie menyimpan kredensial ({name.strip()})",
                    resp=second,
                    payload=value[:120],
                ))

    for link in oauth_links[:5]:
        parsed = urlparse(link)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if "redirect_uri" in query:
            mutated = {k: v[:] for k, v in query.items()}
            mutated["redirect_uri"] = ["https://evil.com/callback"]
            probe = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
            resp = await client.get(probe, follow_redirects=False)
            location = resp.headers.get("location", "") if resp else ""
            if "evil.com" in location:
                findings.append(evidence.from_response(
                    check="auth",
                    severity="high",
                    url=probe,
                    detail="OAuth redirect_uri terbuka",
                    resp=resp,
                    payload="redirect_uri=https://evil.com/callback",
                ))
        if "state" not in query:
            findings.append(evidence.raw(
                check="auth",
                severity="medium",
                url=link,
                detail="OAuth tanpa parameter state (CSRF)",
                request=f"GET {link}",
                response="",
                payload="",
            ))

    for action, code_field in mfa_forms[:3]:
        first = await client.post(action, data={code_field: "000000"})
        second = await client.post(action, data={code_field: "000000"})
        if first and second and _success(first.body) and _success(second.body):
            findings.append(evidence.from_response(
                check="auth",
                severity="high",
                url=action,
                detail="MFA code reuse / weak code diterima",
                resp=second,
                payload=f"{code_field}=000000",
            ))

    return findings
