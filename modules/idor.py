"""IDOR detection by mutating numeric/UUID identifiers."""
from __future__ import annotations

import hashlib
import re
import uuid
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core.http_client import HttpClient
from core.reporter import Finding
from . import evidence

UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
LEN_DELTA = 100
DIGIT_DELTAS = (-1, 1, -10, 10)


def _hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()


def _variants(page: str) -> list[tuple[str, str]]:
    parsed = urlparse(page)
    variants: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(original: str, new_url: str) -> None:
        if new_url != page and new_url not in seen:
            seen.add(new_url)
            variants.append((original, new_url))

    parts = parsed.path.split("/")
    for i, segment in enumerate(parts):
        if segment.isdigit():
            for delta in DIGIT_DELTAS:
                mutated = parts[:]
                mutated[i] = str(max(0, int(segment) + delta))
                add(segment, urlunparse(parsed._replace(path="/".join(mutated))))
        elif UUID_RE.fullmatch(segment):
            for _ in range(2):
                mutated = parts[:]
                mutated[i] = str(uuid.uuid4())
                add(segment, urlunparse(parsed._replace(path="/".join(mutated))))

    params = parse_qs(parsed.query, keep_blank_values=True)
    for key, values in params.items():
        value = values[0] if values else ""
        if value.isdigit():
            for delta in DIGIT_DELTAS:
                mutated = {k: v[:] for k, v in params.items()}
                mutated[key] = [str(max(0, int(value) + delta))]
                add(value, urlunparse(parsed._replace(query=urlencode(mutated, doseq=True))))
        elif UUID_RE.fullmatch(value):
            for _ in range(2):
                mutated = {k: v[:] for k, v in params.items()}
                mutated[key] = [str(uuid.uuid4())]
                add(value, urlunparse(parsed._replace(query=urlencode(mutated, doseq=True))))

    return variants


def _significant(baseline, resp) -> bool:
    if not baseline or baseline.status != 200 or resp.status != 200:
        return False
    length_delta = abs(len(resp.body) - len(baseline.body))
    hash_diff = _hash(resp.body) != _hash(baseline.body)
    return length_delta > LEN_DELTA or (hash_diff and length_delta > 20)


async def run(client: HttpClient, pages: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for page in pages:
        variants = _variants(page)
        if not variants:
            continue
        baseline = await client.get(page)
        if not baseline:
            continue

        reported: set[str] = set()
        for original, variant in variants:
            if original in reported:
                continue
            resp = await client.get(variant)
            if _significant(baseline, resp):
                reported.add(original)
                findings.append(evidence.from_response(
                    check="idor",
                    severity="high",
                    url=variant,
                    detail=f"IDOR: identifier '{original}' diganti neighbor "
                           f"mengembalikan 200 dengan konten berbeda",
                    resp=resp,
                    payload=variant,
                ))

        if baseline.status == 200 and baseline.headers.get("set-cookie"):
            saved = list(client.client.cookies.jar)
            try:
                client.client.cookies.jar.clear()
                noauth = await client.get(page)
            finally:
                for cookie in saved:
                    client.client.cookies.jar.set_cookie(cookie)
            if noauth and noauth.status == 200 and abs(len(noauth.body) - len(baseline.body)) <= 50:
                findings.append(evidence.from_response(
                    check="idor",
                    severity="high",
                    url=page,
                    detail="Resource tetap dapat diakses tanpa session token "
                           "(otorisasi tidak diperiksa)",
                    resp=noauth,
                    payload="(session cookie dihapus)",
                ))

    return findings
