"""Exploit chain synthesis from findings, with loud terminal output."""
from __future__ import annotations

from rich.console import Console

from core.reporter import Finding

console = Console()

CHAINS = {
    "sqli": ("SQLi → dump kredensial → login → upload shell", "critical", [
        "Konfirmasi SQL injection pada parameter yang ditandai",
        "Dump tabel users/credentials (sqlmap --dump)",
        "Crack hash atau gunakan kredensial untuk login",
        "Upload webshell via fitur upload / file manager",
    ]),
    "ssrf": ("SSRF → metadata cloud → kredensial", "critical", [
        "Konfirmasi SSRF ke endpoint internal",
        "Akses metadata cloud (169.254.169.254)",
        "Ambil kredensial IAM/AWS",
        "Gunakan kredensial untuk mengakses resource cloud",
    ]),
    "jwt": ("JWT forgery → admin takeover", "critical", [
        "Konfirmasi kelemahan JWT (alg none / secret lemah)",
        "Forge token dengan role admin",
        "Akses endpoint admin",
    ]),
    "upload": ("Unrestricted upload → RCE", "critical", [
        "Konfirmasi file berbahaya diterima",
        "Akses file yang ter-upload",
        "Eksekusi perintah via webshell",
    ]),
    "cmdi": ("Command injection → RCE", "critical", [
        "Konfirmasi eksekusi perintah pada parameter",
        "Ambil reverse shell / baca file sensitif",
    ]),
    "traversal": ("LFI → baca file sensitif", "high", [
        "Konfirmasi path traversal",
        "Baca /etc/passwd, kunci privat, config",
    ]),
    "idor": ("IDOR → akses data pengguna lain", "high", [
        "Konfirmasi akses objek lintas-akun",
        "Enumerasi ID & akses endpoint admin/user lain",
    ]),
    "open_redirect": ("Open redirect → phishing / bypass filter", "medium", [
        "Konfirmasi redirect ke domain eksternal",
        "Rangkai dengan OAuth untuk curi token",
    ]),
}

LOUD = {
    "sqli": "SQLi ditemukan di {url}! Mencoba ekstrak tabel/user & bypass login...",
    "idor": "IDOR ditemukan di {url}! Mencoba akses endpoint admin/user lain...",
    "jwt": "JWT lemah di {url}! Mencoba forge token admin...",
    "ssrf": "SSRF ditemukan di {url}! Mencoba akses metadata cloud...",
    "traversal": "LFI ditemukan di {url}! Mencoba baca file sensitif...",
    "upload": "Upload berbahaya di {url}! Mencoba akses webshell...",
    "cmdi": "Command injection di {url}! Mencoba eksekusi perintah...",
}


def run(findings: list[Finding], verbose: bool = True) -> list[Finding]:
    by_check: dict[str, list[Finding]] = {}
    for finding in findings:
        by_check.setdefault(finding.check, []).append(finding)

    chains: list[Finding] = []
    for check, (name, severity, steps) in CHAINS.items():
        hits = by_check.get(check)
        if not hits:
            continue
        url = hits[0].url
        if verbose and check in LOUD:
            console.print(f"[bold red]\\[CHAIN][/] [bold yellow]{LOUD[check].format(url=url)}[/]")
        steps_text = "\n".join(f"{i + 1}. {step}" for i, step in enumerate(steps))
        chains.append(Finding(
            check="chain",
            severity=severity,
            url=url,
            detail=name,
            evidence=f"Temuan pemicu: {len(hits)} ({check})\n{steps_text}",
        ))

    if "sqli" in by_check and "upload" in by_check:
        if verbose:
            console.print("[bold red]\\[CHAIN][/] [bold yellow]SQLi + upload → full takeover[/]")
        chains.append(Finding(
            check="chain",
            severity="critical",
            url=by_check["sqli"][0].url,
            detail="SQLi + upload → full takeover",
            evidence="Kombinasi SQLi (ambil kredensial) dan unrestricted upload (RCE).",
        ))
    return chains
