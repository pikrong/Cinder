"""Cinder — Web Vulnerability Scanner (CLI entry point)."""
from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import typer
import yaml
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table

import modules.apischema
import modules.auth
import modules.banner
import modules.cache
import modules.chain
import modules.cmdi
import modules.cors
import modules.csrf
import modules.deser
import modules.domxss
import modules.fuzzer
import modules.graphql
import modules.headers
import modules.idor
import modules.jsrecon
import modules.jwt
import modules.logic
import modules.race
import modules.redirect
import modules.sensitive_files
import modules.smuggle
import modules.sqli
import modules.ssrf
import modules.ssti
import modules.traversal
import modules.triage
import modules.upload
import modules.waf
import modules.xss
from core.crawler import Crawler
from core.fingerprint import fingerprint
from core.http_client import HttpClient, Response
from core.reporter import Finding, Report

app = typer.Typer(add_completion=False, help="Cinder — Web Vulnerability Scanner")
console = Console()


@dataclass
class Config:
    timeout: float = 10.0
    verify_tls: bool = True
    follow_redirects: bool = True
    headers: dict = field(default_factory=lambda: {"User-Agent": "Cinder/1.0"})
    max_depth: int = 2
    max_pages: int = 100
    same_host_only: bool = True
    respect_robots: bool = True
    delay: float = 0.3
    checks: dict = field(default_factory=dict)
    max_urls_to_test: int = 50
    params_to_skip: list = field(default_factory=list)
    report_title: str = "Cinder Scan Report"
    include_evidence: bool = True
    verbose: bool = False
    deep: bool = False
    fuzz: bool = False
    chain: bool = False
    llm_api_key: str = ""
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4o-mini"
    domxss_enabled: bool = False
    chain_enabled: bool = False
    fuzz_enabled: bool = False

    @classmethod
    def load(cls, path: Path | None) -> "Config":
        cfg = cls()
        if path and path.exists():
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            req = raw.get("request", {})
            crawler = raw.get("crawler", {})
            scanner = raw.get("scanner", {})
            report = raw.get("report", {})
            cfg.timeout = float(req.get("timeout", cfg.timeout))
            cfg.verify_tls = bool(req.get("verify_tls", cfg.verify_tls))
            cfg.follow_redirects = bool(req.get("follow_redirects", cfg.follow_redirects))
            if req.get("headers"):
                cfg.headers.update(req["headers"])
            cfg.max_depth = int(crawler.get("max_depth", cfg.max_depth))
            cfg.max_pages = int(crawler.get("max_pages", cfg.max_pages))
            cfg.same_host_only = bool(crawler.get("same_host_only", cfg.same_host_only))
            cfg.respect_robots = bool(crawler.get("respect_robots", cfg.respect_robots))
            cfg.delay = float(crawler.get("delay", cfg.delay))
            cfg.checks = scanner.get("checks", cfg.checks)
            cfg.max_urls_to_test = int(scanner.get("max_urls_to_test", cfg.max_urls_to_test))
            cfg.params_to_skip = scanner.get("params_to_skip", cfg.params_to_skip) or []
            cfg.report_title = report.get("title", cfg.report_title)
            cfg.include_evidence = bool(report.get("include_evidence", cfg.include_evidence))
            cfg.llm_api_key = str(scanner.get("llm_api_key") or cfg.llm_api_key)
            cfg.llm_base_url = str(scanner.get("llm_base_url") or cfg.llm_base_url)
            cfg.llm_model = str(scanner.get("llm_model") or cfg.llm_model)
            cfg.domxss_enabled = bool(scanner.get("domxss_enabled", cfg.domxss_enabled))
            cfg.chain_enabled = bool(scanner.get("chain_enabled", cfg.chain_enabled))
            cfg.fuzz_enabled = bool(scanner.get("fuzz_enabled", cfg.fuzz_enabled))
        return cfg


def _snippet(resp: Response, limit: int = 300) -> tuple[str, str]:
    """Build (request, response) evidence snippets for a finding."""
    req = f"GET {resp.url}\n"
    head = "\n".join(f"{k}: {v}" for k, v in list(resp.headers.items())[:12])
    body = resp.body[:limit]
    return req, f"HTTP {resp.status} ({resp.elapsed * 1000:.0f} ms)\n{head}\n\n{body}"


class Scanner:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.client = HttpClient(
            timeout=cfg.timeout,
            verify=cfg.verify_tls,
            follow_redirects=cfg.follow_redirects,
            headers=cfg.headers,
            verbose=cfg.verbose,
        )
        self.crawler = Crawler(
            self.client,
            max_depth=cfg.max_depth,
            max_pages=cfg.max_pages,
            same_host_only=cfg.same_host_only,
            respect_robots=cfg.respect_robots,
            delay=cfg.delay,
            user_agent=cfg.headers.get("User-Agent", "Cinder/1.0"),
        )
        self.report = Report(target="", title=cfg.report_title)
        self.visited: list[str] = []

    async def close(self) -> None:
        await self.client.close()

    def _add(self, check: str, severity: str, url: str, detail: str,
             resp: Response | None = None, evidence: str = "") -> None:
        request = response = ""
        if resp is not None and self.cfg.include_evidence:
            request, response = _snippet(resp)
        self.report.add(Finding(check, severity, url, detail, evidence, request, response))

    def _attach_evidence(self, finding: Finding) -> None:
        self.report.add(finding)

    async def check_headers(self, url: str) -> None:
        for finding in await modules.headers.run(self.client, url):
            self._attach_evidence(finding)

    async def check_directory_listing(self, url: str) -> None:
        resp = await self.client.get(url)
        if not resp or "html" not in resp.headers.get("content-type", "").lower():
            return
        soup = BeautifulSoup(resp.body, "lxml")
        title = soup.title.get_text(strip=True).lower() if soup.title else ""
        if title.startswith("index of"):
            self._add("directory_listing", "medium", url,
                      "Directory listing terbuka", resp, title[:200])

    async def check_sensitive_files(self, base: str) -> None:
        for finding in await modules.sensitive_files.run(self.client, base):
            self._attach_evidence(finding)

    def _iter_param_urls(self, pages: list[str]) -> Iterable[str]:
        """Yield one URL per testable parameter, for every page (up to --max-pages)."""
        placeholder = "cinder"
        for page in pages[: self.cfg.max_pages]:
            parsed = urlparse(page)
            if not parsed.query:
                continue
            params = parse_qs(parsed.query, keep_blank_values=True)
            seen: set[str] = set()
            for key in params:
                if key in self.cfg.params_to_skip:
                    continue
                mutated = {k: v[:] for k, v in params.items()}
                mutated[key] = [placeholder]
                combo = urlunparse(parsed._replace(query=urlencode(mutated, doseq=True)))
                if combo not in seen:
                    seen.add(combo)
                    yield combo

    def test_targets(self, pages: list[str]) -> list[str]:
        """Unique URLs to test: every discovered parameter of every crawled page."""
        targets: list[str] = []
        seen: set[str] = set()
        for page in pages:
            if page not in seen:
                seen.add(page)
                targets.append(page)
        return targets

    async def check_xss(self, pages: list[str]) -> None:
        for finding in await modules.xss.run(
            self.client, self.test_targets(pages), self.cfg.params_to_skip
        ):
            self._attach_evidence(finding)

    async def check_sqli(self, pages: list[str]) -> None:
        for finding in await modules.sqli.run(
            self.client, self.test_targets(pages), self.cfg.params_to_skip
        ):
            self._attach_evidence(finding)

    async def check_open_redirect(self, pages: list[str]) -> None:
        for finding in await modules.redirect.run(self.client, self.test_targets(pages)):
            self._attach_evidence(finding)

    async def check_traversal(self, pages: list[str]) -> None:
        for finding in await modules.traversal.run(self.client, self.test_targets(pages)):
            self._attach_evidence(finding)

    async def check_jwt(self, pages: list[str]) -> None:
        for finding in await modules.jwt.run(self.client, self.test_targets(pages)):
            self._attach_evidence(finding)

    async def check_idor(self, pages: list[str]) -> None:
        for finding in await modules.idor.run(self.client, self.test_targets(pages)):
            self._attach_evidence(finding)

    async def check_ssrf(self, pages: list[str]) -> None:
        for finding in await modules.ssrf.run(self.client, self.test_targets(pages)):
            self._attach_evidence(finding)

    async def _seed_auth_pages(self, pages: list[str]) -> list[str]:
        if not (self.cfg.headers.get("Authorization") or self.cfg.headers.get("Cookie")):
            return pages
        root = f"{urlparse(pages[0]).scheme}://{urlparse(pages[0]).netloc}" if pages else ""
        for path in ("/admin", "/dashboard", "/api/user", "/account"):
            candidate = root + path
            if candidate in pages:
                continue
            resp = await self.client.get(candidate)
            if resp and resp.status < 400:
                pages.append(candidate)
        return pages

    async def run_deep(self, pages: list[str]) -> None:
        console.print("[dim]  deep scan: semua modul[/]")
        root = self.report.target
        skip = self.cfg.params_to_skip

        schema_findings, schema_endpoints = await modules.apischema.run(self.client, root)
        js_findings, js_endpoints = await modules.jsrecon.run(self.client, pages)
        for finding in schema_findings + js_findings:
            self._attach_evidence(finding)
        for endpoint in schema_endpoints + js_endpoints:
            if endpoint.startswith("http") and endpoint not in pages:
                pages.append(endpoint)

        async def collect(findings: list[Finding]) -> None:
            for finding in findings:
                self._attach_evidence(finding)

        await collect(await modules.cmdi.run(self.client, pages, skip))
        await collect(await modules.ssti.run(self.client, pages, skip))
        await collect(await modules.deser.run(self.client, pages))
        await collect(await modules.cors.run(self.client, pages))
        await collect(await modules.csrf.run(self.client, pages))
        await collect(await modules.graphql.run(self.client, root))
        await collect(await modules.cache.run(self.client, pages))
        await collect(await modules.upload.run(self.client, pages))
        await collect(await modules.logic.run(self.client, pages))
        await collect(await modules.auth.run(self.client, pages))
        await collect(await modules.race.run(self.client, pages))
        await collect(await modules.smuggle.run(root, verbose=self.cfg.verbose))
        await collect(await modules.domxss.run(self.client, pages))

        waf = await modules.waf.run(self.client, root)
        if waf:
            self.report.add(Finding("waf", "info", root, f"WAF terdeteksi: {waf}"))

        self.report.findings = await modules.triage.run(self.client, self.report.findings, self.cfg)

        if self.cfg.chain or self.cfg.chain_enabled:
            for finding in modules.chain.run(self.report.findings):
                self.report.add(finding)

    async def run_fuzz(self, pages: list[str]) -> None:
        console.print("[dim]  fuzzing payload[/]")
        for finding in await modules.fuzzer.run(self.client, pages):
            self._attach_evidence(finding)

    async def run(self, url: str) -> Report:
        if not self.cfg.checks:
            self.cfg.checks = {
                "headers": True, "xss": True, "sqli": True, "open_redirect": True,
                "directory_listing": True, "sensitive_files": True, "traversal": True,
                "jwt": True, "idor": True, "ssrf": True,
            }
        self.report.target = url
        console.print(f"[cyan]→ Memindai[/] {url}")

        pages = await self.crawler.crawl(url)
        pages = await self._seed_auth_pages(pages)
        self.visited = pages
        self.report.pages_crawled = len(pages)
        console.print(f"[dim]  {len(pages)} halaman ditemukan[/]")

        root = await self.client.get(url)
        if root:
            self.report.fingerprint = fingerprint(root)
            if self.report.fingerprint:
                console.print(f"[dim]  fingerprint: {self.report.fingerprint}[/]")

        on = lambda name: self.cfg.checks.get(name, False)
        if on("headers"):
            await self.check_headers(url)
        if on("directory_listing"):
            for page in pages:
                await self.check_directory_listing(page)
        if on("sensitive_files"):
            await self.check_sensitive_files(url)
        if on("xss"):
            await self.check_xss(pages)
        if on("sqli"):
            await self.check_sqli(pages)
        if on("open_redirect"):
            await self.check_open_redirect(pages)
        if on("traversal"):
            await self.check_traversal(pages)
        if on("jwt"):
            await self.check_jwt(pages)
        if on("idor"):
            await self.check_idor(pages)
        if on("ssrf"):
            await self.check_ssrf(pages)
        if self.cfg.deep:
            await self.run_deep(pages)
        if self.cfg.fuzz or self.cfg.fuzz_enabled:
            await self.run_fuzz(pages)
        if (self.cfg.chain or self.cfg.chain_enabled) and not self.cfg.deep:
            for finding in modules.chain.run(self.report.findings):
                self.report.add(finding)
        return self.report


def _severity_style(sev: str) -> str:
    return {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim", "info": "cyan"}.get(sev, "white")


def render_summary(report: Report) -> None:
    c = report.counts
    console.print(
        f"[dim]{len(report.findings)} temuan di {report.pages_crawled} halaman — "
        f"[bold red]critical {c['critical']}[/], "
        f"[bold red]high {c['high']}[/], "
        f"[yellow]medium {c['medium']}[/], "
        f"[dim]low {c['low']}[/], info {c['info']}[/]"
    )


def render_terminal(report: Report) -> None:
    if not report.findings:
        console.print("[bold green]✓ Tidak ada temuan.[/]")
        render_summary(report)
        return
    table = Table(title="Cinder Findings", show_lines=True)
    table.add_column("Severity", style="bold")
    table.add_column("Check")
    table.add_column("URL", overflow="fold")
    table.add_column("Detail", overflow="fold")
    for f in report.findings:
        table.add_row(f"[{_severity_style(f.severity)}]{f.severity}[/]", f.check, f.url, f.detail)
    console.print(table)
    render_summary(report)


@app.command()
def scan(
    url: str = typer.Option(..., "-u", "--url", help="URL target yang akan dipindai."),
    output: Path | None = typer.Option(None, "-o", "--output", help="Simpan laporan ke file."),
    as_json: bool = typer.Option(False, "--json", help="Keluarkan laporan dalam format JSON."),
    as_html: bool = typer.Option(False, "--html", help="Simpan laporan HTML (default jika -o berakhiran .html)."),
    config: Path = typer.Option(Path("config.yaml"), "--config", help="Path file konfigurasi."),
    depth: int | None = typer.Option(None, "--depth", help="Batas kedalaman crawl."),
    max_pages: int | None = typer.Option(None, "--max-pages", help="Batas jumlah halaman."),
    timeout: float | None = typer.Option(None, "--timeout", help="Timeout per-request (detik)."),
    ignore_robots: bool = typer.Option(False, "--ignore-robots", help="Abaikan robots.txt."),
    verbose: bool = typer.Option(False, "--verbose", help="Log setiap request ke stderr."),
    deep: bool = typer.Option(False, "--deep", help="Jalankan semua modul lanjutan."),
    fuzz: bool = typer.Option(False, "--fuzz", help="Fuzzing payload ke semua parameter."),
    chain: bool = typer.Option(False, "--chain", help="Sintesis exploit chain dari temuan."),
    auth_token: str | None = typer.Option(None, "--auth-token", help="Bearer token untuk sesi terautentikasi."),
    cookie: str | None = typer.Option(None, "--cookie", help="Cookie sesi (format 'name=value; ...')."),
    header: list[str] = typer.Option([], "--header", help="Header tambahan 'Key: Value' (boleh diulang)."),
    no_banner: bool = typer.Option(False, "--no-banner", help="Sembunyikan banner."),
) -> None:
    """Pindai URL target dan laporkan kerentanan web."""
    if not url.startswith(("http://", "https://")):
        console.print("[red]Error:[/] URL harus diawali http:// atau https://")
        raise typer.Exit(code=2)

    cfg = Config.load(config if config.exists() else None)
    if depth is not None:
        cfg.max_depth = depth
    if max_pages is not None:
        cfg.max_pages = max_pages
    if timeout is not None:
        cfg.timeout = timeout
    if ignore_robots:
        cfg.respect_robots = False
    cfg.verbose = verbose
    cfg.deep = deep
    cfg.fuzz = fuzz
    cfg.chain = chain

    if auth_token:
        token = auth_token if auth_token.lower().startswith("bearer ") else f"Bearer {auth_token}"
        cfg.headers["Authorization"] = token
    if cookie:
        cfg.headers["Cookie"] = cookie
    for raw_header in header:
        name, sep, value = raw_header.partition(":")
        if sep and name.strip():
            cfg.headers[name.strip()] = value.strip()

    async def _run() -> Report:
        scanner = Scanner(cfg)
        try:
            return await scanner.run(url)
        finally:
            await scanner.close()

    report = asyncio.run(_run())

    html_out = as_html or (output is not None and output.suffix.lower() in (".html", ".htm"))

    if html_out:
        target = output or Path(f"{urlparse(url).netloc or 'report'}.html")
        report.write_html(target)
        render_terminal(report)
        console.print(f"[green]✓[/] Laporan HTML disimpan: {target}")
    elif as_json:
        if output:
            report.write_json(output)
            console.print(f"[green]✓[/] Laporan JSON disimpan: {output}")
        else:
            console.print_json(data=report.to_dict())
    else:
        render_terminal(report)
        if output:
            report.write_json(output)
            console.print(f"[green]✓[/] Laporan disimpan: {output}")

    if any(f.severity in ("high", "critical") for f in report.findings):
        raise typer.Exit(code=1)


if __name__ == "__main__":
    if "--no-banner" not in sys.argv:
        modules.banner.show_banner(console)
    app()
