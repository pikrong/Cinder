"""Passive technology fingerprinting from headers, cookies, HTML, error pages."""
from __future__ import annotations

import re

from bs4 import BeautifulSoup

from .http_client import Response

_COOKIE_SIGNATURES = {
    "phpsessid": ("language", "PHP"),
    "jsessionid": ("language", "Java"),
    "asp.net_sessionid": ("language", "ASP.NET"),
    "aspsessionid": ("language", "ASP Classic"),
    "laravel_session": ("framework", "Laravel"),
    "ci_session": ("framework", "CodeIgniter"),
    "django_session": ("framework", "Django"),
    "connect.sid": ("framework", "Express/Node.js"),
    "wordpress_logged_in": ("cms", "WordPress"),
    "wp-settings": ("cms", "WordPress"),
    "joomla_": ("cms", "Joomla"),
    "_shopify_s": ("cms", "Shopify"),
}

_GENERATOR = {
    "wordpress": ("cms", "WordPress"),
    "joomla": ("cms", "Joomla"),
    "drupal": ("cms", "Drupal"),
    "typo3": ("cms", "TYPO3"),
    "hugo": ("cms", "Hugo"),
    "ghost": ("cms", "Ghost"),
    "django": ("framework", "Django"),
    "next.js": ("framework", "Next.js"),
}

_ERROR_SIGNATURES = [
    (re.compile(r"<address>Apache/[\d.]+", re.I), ("server", "Apache")),
    (re.compile(r"nginx/[\d.]+", re.I), ("server", "nginx")),
    (re.compile(r"Microsoft-IIS/[\d.]+", re.I), ("server", "IIS")),
    (re.compile(r"LiteSpeed", re.I), ("server", "LiteSpeed")),
    (re.compile(r"X-Powered-By|ASP\.NET", re.I), ("language", "ASP.NET")),
    (re.compile(r"<b>Warning</b>:\s.*?on line <b>\d+", re.I), ("language", "PHP")),
    (re.compile(r"Traceback \(most recent call last\)", re.I), ("language", "Python")),
    (re.compile(r"(Werkzeug|Pallets)", re.I), ("framework", "Flask/Werkzeug")),
    (re.compile(r"Ruby on Rails|ActionController", re.I), ("framework", "Ruby on Rails")),
]


def _add(result: dict[str, set[str]], category: str, value: str) -> None:
    result.setdefault(category, set()).add(value)


def fingerprint(resp: Response) -> dict[str, list[str]]:
    """Return {category: [values]} for server/framework/cms/language."""
    result: dict[str, set[str]] = {}
    if not resp:
        return {}

    headers = {k.lower(): v for k, v in resp.headers.items()}

    server = headers.get("server", "")
    if server:
        _add(result, "server", server.split("/")[0].split(" ")[0])
    powered = headers.get("x-powered-by", "")
    if powered:
        _add(result, "language", powered.split("/")[0])

    for name, value in resp.headers.items():
        low = name.lower()
        if low == "set-cookie":
            cookie_name = value.split("=", 1)[0].strip().lower()
            for sig, (cat, tech) in _COOKIE_SIGNATURES.items():
                if sig in cookie_name:
                    _add(result, cat, tech)

    soup = BeautifulSoup(resp.body, "lxml")
    generator = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
    if generator and generator.get("content"):
        content = generator["content"].lower()
        for key, (cat, tech) in _GENERATOR.items():
            if key in content:
                _add(result, cat, tech)

    for pattern, (cat, tech) in _ERROR_SIGNATURES:
        if pattern.search(resp.body):
            _add(result, cat, tech)

    return {cat: sorted(vals) for cat, vals in result.items()}
