"""CSRF token analysis on POST forms."""
from __future__ import annotations

from urllib.parse import urljoin

from bs4 import BeautifulSoup

from core.http_client import HttpClient
from core.reporter import Finding
from . import common, evidence

TOKEN_HINTS = ("csrf", "token", "authenticity", "nonce", "_token")


def _hidden(soup: BeautifulSoup) -> dict[str, str]:
    values = {}
    for inp in soup.find_all("input"):
        name = inp.get("name")
        if name and (inp.get("type") or "").lower() == "hidden":
            values[name] = inp.get("value") or ""
    return values


async def run(client: HttpClient, pages: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for page in pages:
        resp = await client.get(page)
        if not resp:
            continue
        soup = BeautifulSoup(resp.body, "lxml")
        for form in soup.find_all("form"):
            if (form.get("method") or "get").lower() != "post":
                continue
            action = urljoin(page, form.get("action") or page)
            hidden = _hidden(soup)
            tokens = {k: v for k, v in hidden.items() if common.hint(k, TOKEN_HINTS)}

            if not tokens:
                findings.append(evidence.from_response(
                    check="csrf",
                    severity="medium",
                    url=action,
                    detail="Form POST tanpa token CSRF",
                    resp=resp,
                ))
                continue

            second = await client.get(page)
            if not second:
                continue
            repeated = [k for k, v in tokens.items() if _hidden(BeautifulSoup(second.body, "lxml")).get(k) == v]
            if repeated:
                findings.append(evidence.from_response(
                    check="csrf",
                    severity="medium",
                    url=action,
                    detail=f"Token CSRF tidak unik antar-request: {', '.join(repeated)}",
                    resp=second,
                ))
    return findings
