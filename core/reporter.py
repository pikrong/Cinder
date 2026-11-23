"""Finding collection and JSON/HTML/SARIF report generation."""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

DEFAULT_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "report"

# Central severity/meta catalogue: filled for every finding that doesn't set its own.
CHECK_META: dict[str, dict] = {
    "sqli": {"cwe": "CWE-89", "owasp": "A03:2021 Injection",
             "remediation": "Gunakan prepared statement/parameterized query; jangan menyusun SQL dari input pengguna."},
    "xss": {"cwe": "CWE-79", "owasp": "A03:2021 Injection",
            "remediation": "Encode output sesuai konteks, gunakan CSP, dan hindari innerHTML dengan data tak tepercaya."},
    "cmdi": {"cwe": "CWE-78", "owasp": "A03:2021 Injection",
             "remediation": "Hindari system()/shell; gunakan API tanpa shell dan validasi allowlist input."},
    "ssti": {"cwe": "CWE-1336", "owasp": "A03:2021 Injection",
             "remediation": "Jangan render template dari input pengguna; gunakan sandbox/autoescape."},
    "traversal": {"cwe": "CWE-22", "owasp": "A01:2021 Broken Access Control",
                  "remediation": "Normalisasi path, tolak '..' dan path absolut; gunakan allowlist direktori."},
    "redirect": {"cwe": "CWE-601", "owasp": "A01:2021 Broken Access Control",
                 "remediation": "Validasi tujuan redirect terhadap allowlist domain internal."},
    "idor": {"cwe": "CWE-639", "owasp": "A01:2021 Broken Access Control",
             "remediation": "Terapkan otorisasi per-objek di server, jangan hanya menyembunyikan ID."},
    "ssrf": {"cwe": "CWE-918", "owasp": "A10:2021 Server-Side Request Forgery",
             "remediation": "Validasi URL, blokir IP internal/metadata, gunakan allowlist keluar."},
    "jwt": {"cwe": "CWE-347", "owasp": "A02:2021 Cryptographic Failures",
            "remediation": "Tolak alg none, verifikasi signature dengan kunci yang benar, gunakan secret kuat."},
    "deser": {"cwe": "CWE-502", "owasp": "A08:2021 Software and Data Integrity Failures",
              "remediation": "Jangan deserialisasi data tak tepercaya; gunakan format data aman (JSON)."},
    "upload": {"cwe": "CWE-434", "owasp": "A04:2021 Insecure Design",
               "remediation": "Validasi tipe/ekstensi file, simpan di luar webroot, non-eksekusi."},
    "cors": {"cwe": "CWE-942", "owasp": "A05:2021 Security Misconfiguration",
             "remediation": "Batasi Access-Control-Allow-Origin ke domain tepercaya; jangan pantulkan Origin."},
    "csrf": {"cwe": "CWE-352", "owasp": "A01:2021 Broken Access Control",
             "remediation": "Gunakan token anti-CSRF unik per sesi dan SameSite cookie."},
    "cache": {"cwe": "CWE-525", "owasp": "A05:2021 Security Misconfiguration",
              "remediation": "Jangan gunakan header host yang dikontrol klien untuk membangun konten cache."},
    "smuggle": {"cwe": "CWE-444", "owasp": "A05:2021 Security Misconfiguration",
                "remediation": "Normalisasi Content-Length/Transfer-Encoding di edge/proxy."},
    "race": {"cwe": "CWE-362", "owasp": "A04:2021 Insecure Design",
             "remediation": "Gunakan locking/atomics/transaksi untuk operasi sensitif."},
    "logic": {"cwe": "CWE-840", "owasp": "A04:2021 Insecure Design",
              "remediation": "Validasi harga/jumlah di server, jangan percaya nilai dari klien."},
    "domxss": {"cwe": "CWE-79", "owasp": "A03:2021 Injection",
               "remediation": "Hindari sink DOM berbahaya (innerHTML, eval) dengan data tak tepercaya."},
    "graphql": {"cwe": "CWE-200", "owasp": "A01:2021 Broken Access Control",
                "remediation": "Nonaktifkan introspection di produksi, batasi batching/kompleksitas query."},
    "apischema": {"cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration",
                  "remediation": "Jangan ekspos dokumentasi API di produksi; lindungi dengan auth."},
    "dir_fuzz": {"cwe": "CWE-200", "owasp": "A05:2021 Security Misconfiguration",
                 "remediation": "Hapus/ lindungi path sensitif; nonaktifkan directory listing."},
    "sensitive_files": {"cwe": "CWE-538", "owasp": "A05:2021 Security Misconfiguration",
                        "remediation": "Hapus file sensitif (.env, .git) dari webroot."},
    "headers": {"cwe": "CWE-693", "owasp": "A05:2021 Security Misconfiguration",
                "remediation": "Tambahkan header keamanan (CSP, HSTS, X-Frame-Options, dll)."},
    "cookies": {"cwe": "CWE-614", "owasp": "A05:2021 Security Misconfiguration",
                "remediation": "Set flag Secure, HttpOnly, SameSite pada cookie sensitif."},
    "jsrecon": {"cwe": "CWE-540", "owasp": "A05:2021 Security Misconfiguration",
                "remediation": "Jangan hardcode secret di JS; hapus source map di produksi."},
    "auth": {"cwe": "CWE-287", "owasp": "A07:2021 Identification and Authentication Failures",
             "remediation": "Perbaiki alur autentikasi, token acak kuat, binding sesi."},
    "fuzz": {"cwe": "CWE-20", "owasp": "A03:2021 Injection",
             "remediation": "Validasi dan sanitasi semua input."},
    "waf": {"cwe": "CWE-693", "owasp": "A05:2021 Security Misconfiguration",
            "remediation": "Pertahankan WAF, tapi perbaiki akar kerentanan di aplikasi."},
    "chain": {"cwe": "CWE-693", "owasp": "A04:2021 Insecure Design",
              "remediation": "Putus rantai eksploitasi dengan memperbaiki tiap temuan pemicu."},
}

SEVERITY_CONFIDENCE = {"critical": "high", "high": "medium", "medium": "medium", "low": "low", "info": "low"}

REDACT_KEYS = ("password", "passwd", "token", "cookie", "authorization", "secret", "api_key", "apikey", "set-cookie")
_REDACT_RE = re.compile(
    r"(?im)^(\s*(?:" + "|".join(REDACT_KEYS) + r")\s*[:=]\s*)(.+)$"
)


def redact(text: str) -> str:
    """Mask sensitive header/body values (password, token, cookie, authorization)."""
    if not text:
        return text
    return _REDACT_RE.sub(lambda m: f"{m.group(1)}[REDACTED]", text)


@dataclass
class Finding:
    check: str
    severity: str
    url: str
    detail: str
    evidence: str = ""
    request: str = ""
    response: str = ""
    payload: str = ""
    timestamp: str = ""
    reproduction: str = ""
    confidence: str = ""
    cwe: str = ""
    owasp: str = ""
    remediation: str = ""


@dataclass
class Report:
    target: str
    pages_crawled: int = 0
    findings: list[Finding] = field(default_factory=list)
    fingerprint: dict = field(default_factory=dict)
    title: str = "Cinder Scan Report"
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def add(self, finding: Finding) -> None:
        meta = CHECK_META.get(finding.check, {})
        if not finding.cwe:
            finding.cwe = meta.get("cwe", "")
        if not finding.owasp:
            finding.owasp = meta.get("owasp", "")
        if not finding.remediation:
            finding.remediation = meta.get("remediation", "")
        if not finding.confidence:
            finding.confidence = SEVERITY_CONFIDENCE.get(finding.severity, "medium")
        self.findings.append(finding)

    @property
    def counts(self) -> dict[str, int]:
        out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "target": self.target,
            "generated_at": self.generated_at,
            "pages_crawled": self.pages_crawled,
            "fingerprint": self.fingerprint,
            "counts": self.counts,
            "finding_count": len(self.findings),
            "findings": [asdict(f) for f in self.findings],
        }

    def write_json(self, path: Path) -> None:
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    def _redacted_dict(self) -> dict:
        data = self.to_dict()
        for item in data["findings"]:
            for key in ("request", "response", "evidence"):
                item[key] = redact(item.get(key, ""))
        return data

    def render_html(self, template_dir: Path = DEFAULT_TEMPLATE_DIR) -> str:
        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template("template.html")
        return template.render(report=self._redacted_dict())

    def write_html(self, path: Path, template_dir: Path = DEFAULT_TEMPLATE_DIR) -> None:
        path.write_text(self.render_html(template_dir), encoding="utf-8")

    def to_sarif(self) -> dict:
        level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
        rules = {}
        results = []
        for f in self.findings:
            rule_id = f.check
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": f.check},
                    "help": {"text": f.remediation or f.check},
                    "properties": {
                        "tags": [t for t in (f.cwe, f.owasp) if t],
                        "security-severity": _sarif_score(f.severity),
                    },
                }
            results.append({
                "ruleId": rule_id,
                "level": level.get(f.severity, "note"),
                "message": {"text": f"{f.detail}\n[CWE: {f.cwe or '-'} | OWASP: {f.owasp or '-'}]"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.url},
                }}],
                "properties": {
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "cwe": f.cwe,
                    "owasp": f.owasp,
                },
            })
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "Cinder",
                    "informationUri": "https://github.com/your-org/cinder",
                    "rules": list(rules.values()),
                }},
                "results": results,
            }],
        }

    def write_sarif(self, path: Path) -> None:
        path.write_text(
            json.dumps(self.to_sarif(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


def _sarif_score(severity: str) -> str:
    return {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}.get(severity, "0.0")
