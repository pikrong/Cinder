"""Shared helpers for scanner modules."""
from __future__ import annotations

import json
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


def parse_json(text: str) -> object | None:
    try:
        return json.loads(text)
    except Exception:
        return None


def json_scalar_paths(data: object, prefix: str = "") -> list[tuple[str, object]]:
    """Return [(json_path, value)] for every scalar leaf in a JSON document."""
    out: list[tuple[str, object]] = []
    if isinstance(data, dict):
        for key, value in data.items():
            path = f"{prefix}/{key}" if prefix else str(key)
            out.extend(json_scalar_paths(value, path))
    elif isinstance(data, list):
        for index, value in enumerate(data):
            path = f"{prefix}/{index}"
            out.extend(json_scalar_paths(value, path))
    else:
        out.append((prefix, data))
    return out


def json_set(data: object, path: str, value: object) -> object:
    """Set a value at a JSON path produced by `json_scalar_paths` (copy semantics)."""
    parts = path.split("/")
    node = data
    for part in parts[:-1]:
        node = node[int(part)] if isinstance(node, list) else node[part]
    last = parts[-1]
    if isinstance(node, list):
        node[int(last)] = value
    else:
        node[last] = value
    return data


def api_request(method: str, url: str, body: str, headers: dict | None = None) -> dict:
    """Canonical description of a captured API/XHR request."""
    return {"method": method.upper(), "url": url, "body": body,
            "headers": dict(headers or {})}
