"""Exploit chain synthesis from findings."""
from __future__ import annotations

from core.reporter import Finding

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
        "Enumerasi ID untuk mengambil data massal",
    ]),
    "open_redirect": ("Open redirect → phishing / bypass filter", "medium", [
        "Konfirmasi redirect ke domain eksternal",
        "Rangkai dengan OAuth untuk curi token",
    ]),
}


def run(findings: list[Finding]) -> list[Finding]:
    by_check: dict[str, list[Finding]] = {}
    for finding in findings:
        by_check.setdefault(finding.check, []).append(finding)

    chains: list[Finding] = []
    for check, (name, severity, steps) in CHAINS.items():
        hits = by_check.get(check)
        if not hits:
            continue
        steps_text = "\n".join(f"{i + 1}. {step}" for i, step in enumerate(steps))
        chains.append(Finding(
            check="chain",
            severity=severity,
            url=hits[0].url,
            detail=name,
            evidence=f"Temuan pemicu: {len(hits)} ({check})\n{steps_text}",
        ))

    if "sqli" in by_check and "upload" in by_check:
        chains.append(Finding(
            check="chain",
            severity="critical",
            url=by_check["sqli"][0].url,
            detail="SQLi + upload → full takeover",
            evidence="Kombinasi SQLi (ambil kredensial) dan unrestricted upload (RCE).",
        ))
    return chains
