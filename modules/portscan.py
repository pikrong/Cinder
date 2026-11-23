"""Nmap-style TCP port scan with service banner grabbing (async)."""
from __future__ import annotations

import asyncio
import ssl
from urllib.parse import urlparse

from core.reporter import Finding

PORTS = (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 1433, 3306, 3389, 8080, 8443)
SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 443: "https",
    445: "smb", 1433: "mssql", 3306: "mysql", 3389: "rdp", 8080: "http-alt",
    8443: "https-alt",
}
TLS_PORTS = {443, 8443}
TIMEOUT = 3.0
MAX_CONCURRENCY = 20


async def _grab_banner(host: str, port: int) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), TIMEOUT
        )
    except Exception:
        return ""
    try:
        if port in TLS_PORTS:
            try:
                await writer.start_tls(ssl.create_default_context())
            except Exception:
                pass
        try:
            data = await asyncio.wait_for(reader.read(256), 1.5)
            return data.decode("latin-1", "replace").strip().splitlines()[0][:120] if data else ""
        except Exception:
            return ""
    finally:
        writer.close()


async def run(base_url: str, progress_cb=None) -> list[Finding]:
    parsed = urlparse(base_url)
    host = parsed.hostname
    if not host:
        return []
    sem = asyncio.Semaphore(MAX_CONCURRENCY)
    findings: list[Finding] = []
    done = 0
    total = len(PORTS)

    async def probe(port: int) -> None:
        nonlocal done
        async with sem:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), TIMEOUT
                )
                writer.close()
                open_port = True
            except Exception:
                open_port = False
            done += 1
            if progress_cb:
                progress_cb(done, total)
            if not open_port:
                return
            banner = await _grab_banner(host, port)
            service = SERVICE_NAMES.get(port, "unknown")
            findings.append(Finding(
                check="portscan",
                severity="info",
                url=f"{parsed.scheme}://{host}:{port}",
                detail=f"Port {port}/{service} terbuka" + (f" — banner: {banner}" if banner else ""),
                request=f"TCP connect {host}:{port}",
                response=banner,
                confidence="high",
            ))

    await asyncio.gather(*[probe(port) for port in PORTS])
    return findings
