"""Finding triage: dedup, signature cross-validation, optional LLM review."""
from __future__ import annotations

import json

from core.http_client import HttpClient
from core.reporter import Finding

SIGNATURES = {
    "sqli": ("SQL syntax", "mysql_", "ORA-", "PostgreSQL", "SQLite", "OLE DB"),
    "xss": ("<svg", "onerror=", "onmouseover=", "alert(1)"),
    "cmdi": ("uid=", "root:x:"),
    "ssti": ("7777777", "49"),
    "traversal": ("root:x:0:0:",),
    "ssrf": ("ami-id", "instance-id", "root:x:0:0:", "SSH-"),
}

VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")
LLM_LIMIT = 15


def _dedup(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.check, finding.url, finding.detail)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _cross_validate(finding: Finding) -> Finding:
    needles = SIGNATURES.get(finding.check)
    if not needles:
        return finding
    blob = (finding.response or "") + (finding.evidence or "")
    if any(needle.lower() in blob.lower() for needle in needles):
        return finding
    finding.detail += " [low-confidence: signature tidak ditemukan di evidence]"
    return finding


async def _ask(client: HttpClient, cfg, finding: Finding) -> None:
    prompt = (
        'Analisa temuan scanner berikut. Balas JSON: {"false_positive": bool, '
        '"severity": "critical|high|medium|low|info", "explanation": "..."}.\n'
        f"Check: {finding.check}\nURL: {finding.url}\nDetail: {finding.detail}\n"
        f"Evidence: {(finding.response or finding.evidence or '')[:800]}"
    )
    payload = {
        "model": getattr(cfg, "llm_model", "gpt-4o-mini"),
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
    }
    headers = {"Authorization": f"Bearer {cfg.llm_api_key}", "Content-Type": "application/json"}
    base = getattr(cfg, "llm_base_url", "https://api.openai.com/v1").rstrip("/")
    resp = await client.post(f"{base}/chat/completions", json=payload, headers=headers)
    if not resp or resp.status != 200:
        return
    try:
        verdict = json.loads(json.loads(resp.body)["choices"][0]["message"]["content"])
    except Exception:
        return
    if verdict.get("false_positive"):
        finding.severity = "info"
        finding.detail += " [LLM: kemungkinan false positive]"
    if verdict.get("severity") in VALID_SEVERITIES:
        finding.severity = verdict["severity"]
    if verdict.get("explanation"):
        finding.evidence = (finding.evidence or "") + f"\nllm: {verdict['explanation']}"


async def run(client: HttpClient, findings: list[Finding], cfg) -> list[Finding]:
    findings = [_cross_validate(finding) for finding in _dedup(findings)]
    key = getattr(cfg, "llm_api_key", "")
    if not key:
        return findings
    for finding in findings[:LLM_LIMIT]:
        await _ask(client, cfg, finding)
    return findings
