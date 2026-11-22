"""SQL injection detection: error-based, boolean-based, time-based, union."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from core.http_client import HttpClient
from core.reporter import Finding
from . import evidence

PAYLOAD_FILE = Path(__file__).resolve().parent.parent / "payloads" / "sqli.txt"

ERROR_SIGNATURES = {
    "mysql": [
        re.compile(r"SQL syntax.*MySQL", re.I),
        re.compile(r"Warning.*mysql_", re.I),
        re.compile(r"check the manual that corresponds to your MySQL", re.I),
    ],
    "mssql": [
        re.compile(r"Microsoft OLE DB Provider", re.I),
        re.compile(r"Unclosed quotation mark", re.I),
        re.compile(r"Incorrect syntax near", re.I),
    ],
    "postgresql": [
        re.compile(r"PostgreSQL.*ERROR", re.I),
        re.compile(r"Warning.*pg_", re.I),
        re.compile(r"unterminated quoted string", re.I),
    ],
    "oracle": [
        re.compile(r"ORA-[0-9]{4,}"),
        re.compile(r"Oracle error", re.I),
        re.compile(r"Oracle.*Driver", re.I),
    ],
    "sqlite": [
        re.compile(r"SQLite/JDBCDriver", re.I),
        re.compile(r"System\.Data\.SQLite\.SQLiteException", re.I),
        re.compile(r"sqlite_", re.I),
    ],
}

TIME_PAYLOADS = [
    ("mysql", "' OR SLEEP(5)-- "),
    ("mssql", "'; WAITFOR DELAY '0:0:5'-- "),
    ("postgresql", "' OR pg_sleep(5)-- "),
]
TIME_THRESHOLD = 4.5

BOOL_TRUE = "' AND 1=1-- "
BOOL_FALSE = "' AND 1=2-- "
BOOL_LEN_DELTA = 300
BOOL_FALSE_DELTA = 50

UNION_MAX_COLUMNS = 10


def _load_payloads() -> list[tuple[str, str, str]]:
    """Return [(technique, dialect, payload)] from payloads/sqli.txt."""
    if not PAYLOAD_FILE.exists():
        return []
    out = []
    for line in PAYLOAD_FILE.read_text().splitlines():
        line = line.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        # Keep the payload verbatim (trailing space is part of SQL comment syntax).
        technique, sep1, rest = line.partition("|")
        dialect, sep2, payload = rest.partition("|")
        if not sep1 or not sep2 or not payload.strip():
            continue
        out.append((technique.strip(), dialect.strip(), payload.lstrip()))
    return out


def _inject(url: str, key: str, payload: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    mutated = {k: v[:] for k, v in params.items()}
    mutated[key] = [payload]
    return urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))


def _fingerprint_body(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", "ignore")).hexdigest()


def _match_error(body: str) -> str | None:
    for dialect, patterns in ERROR_SIGNATURES.items():
        for pat in patterns:
            if pat.search(body):
                return dialect
    return None


def _param_keys(url: str, skip: list[str]) -> list[str]:
    parsed = urlparse(url)
    if not parsed.query:
        return []
    return [k for k in parse_qs(parsed.query, keep_blank_values=True) if k not in skip]


async def _error_based(client, url, key, payloads, findings, tick) -> bool:
    for technique, dialect, payload in payloads:
        if technique != "error":
            continue
        tick()
        probe = _inject(url, key, payload)
        resp = await client.get(probe)
        if not resp:
            continue
        matched = _match_error(resp.body)
        if matched:
            findings.append(evidence.from_response(
                check="sqli",
                severity="high",
                url=probe,
                detail=f"Error-based SQLi ({matched}) via parameter '{key}'",
                resp=resp,
                payload=payload,
            ))
            return True
    return False


async def _boolean_based(client, url, key, baseline, findings, tick) -> bool:
    tick()
    true_probe = _inject(url, key, BOOL_TRUE)
    resp_true = await client.get(true_probe)
    tick()
    resp_false = await client.get(_inject(url, key, BOOL_FALSE))
    if not resp_true or not resp_false or baseline is None:
        return False

    base_len = len(baseline.body)
    true_len = len(resp_true.body)
    false_len = len(resp_false.body)
    # true must resemble the original page; false must diverge from true.
    true_close = abs(true_len - base_len) <= BOOL_LEN_DELTA
    false_differs = abs(false_len - true_len) > BOOL_FALSE_DELTA
    status_diff = resp_true.status != resp_false.status
    hash_diff = _fingerprint_body(resp_true.body) != _fingerprint_body(resp_false.body)

    if true_close and false_differs and (status_diff or hash_diff):
        finding = evidence.from_response(
            check="sqli",
            severity="high",
            url=true_probe,
            detail=f"Boolean-based SQLi via parameter '{key}' "
                   f"(true≈baseline, false differs)",
            resp=resp_true,
            payload=BOOL_TRUE,
        )
        finding.evidence += (
            f"\nfalse: {BOOL_FALSE!r} len={false_len} status={resp_false.status}"
            f"\nbaseline len={base_len}"
        )
        findings.append(finding)
        return True
    return False


async def _time_based(client, url, key, findings, tick) -> bool:
    for dialect, payload in TIME_PAYLOADS:
        tick()
        probe = _inject(url, key, payload)
        resp = await client.get(probe)
        if resp and resp.elapsed > TIME_THRESHOLD:
            findings.append(evidence.from_response(
                check="sqli",
                severity="high",
                url=probe,
                detail=f"Time-based SQLi ({dialect}) via parameter '{key}' "
                       f"(elapsed {resp.elapsed:.2f}s)",
                resp=resp,
                payload=payload,
            ))
            return True
    return False


async def _union_based(client, url, key, baseline, findings, tick) -> bool:
    if baseline is None:
        return False
    base_error = _match_error(baseline.body)
    base_len = len(baseline.body)
    prev_error = True
    for cols in range(1, UNION_MAX_COLUMNS + 1):
        tick()
        payload = "' UNION SELECT " + ",".join(["NULL"] * cols) + "-- "
        probe = _inject(url, key, payload)
        resp = await client.get(probe)
        if not resp:
            continue
        now_error = _match_error(resp.body)
        # Column count hit when the SQL error disappears and the response shifts.
        if prev_error and not now_error and abs(len(resp.body) - base_len) > BOOL_LEN_DELTA:
            findings.append(evidence.from_response(
                check="sqli",
                severity="high",
                url=probe,
                detail=f"UNION-based SQLi via parameter '{key}' "
                       f"({cols} columns, error cleared)",
                resp=resp,
                payload=payload,
            ))
            return True
        prev_error = now_error
    return False


async def run(
    client: HttpClient,
    pages: list[str],
    skip: list[str] | None = None,
    progress_cb: Callable[[int, int], None] | None = None,
) -> list[Finding]:
    skip = skip or []
    payloads = _load_payloads()
    findings: list[Finding] = []

    error_count = sum(1 for technique, _, _ in payloads if technique == "error")
    per_param = error_count + 2 + len(TIME_PAYLOADS) + UNION_MAX_COLUMNS
    units = [(page, key) for page in pages for key in _param_keys(page, skip)]
    total = per_param * len(units) or 1

    sent = 0

    def tick() -> None:
        nonlocal sent
        sent += 1
        if progress_cb:
            progress_cb(sent, total)

    for page, key in units:
        baseline = await client.get(page)
        if await _error_based(client, page, key, payloads, findings, tick):
            continue
        if await _boolean_based(client, page, key, baseline, findings, tick):
            continue
        if await _time_based(client, page, key, findings, tick):
            continue
        await _union_based(client, page, key, baseline, findings, tick)

    return findings
