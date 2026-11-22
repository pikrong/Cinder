"""Shared helpers for scanner modules."""
from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


def params(url: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(url).query, keep_blank_values=True)


def param_keys(url: str, skip: list[str] | None = None) -> list[str]:
    skip = skip or []
    return [key for key in params(url) if key not in skip]


def inject(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    query = params(url)
    mutated = {k: v[:] for k, v in query.items()}
    mutated[key] = [value]
    return urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))


def origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def hint(name: str, hints: tuple[str, ...] | list[str]) -> bool:
    low = name.lower()
    return any(h in low for h in hints)


def total(body: str) -> float | None:
    match = re.search(
        r"(?:total|amount|price|subtotal)[^0-9\-]{0,24}(-?[0-9][0-9.,]*)", body, re.I
    )
    if not match:
        return None
    try:
        return float(match.group(1).replace(",", ""))
    except ValueError:
        return None
