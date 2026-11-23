"""Cinder — Web Vulnerability Scanner (CLI entry point)."""
from __future__ import annotations

import asyncio
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable
from urllib.parse import urlparse

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
import modules.dir_fuzz
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
import modules.portscan
import modules.sensitive_files
import modules.server_audit
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
from core.progress import ScanProgress
from core.reporter import Finding, Report
from core import template_engine

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
    login_url: str = ""
    login_user_field: str = "username"
    login_pass_field: str = "password"
    username: str = ""
    password: str = ""
    async_mode: bool = False
    max_concurrency: int = 10
    proxies: list = field(default_factory=list)
    stealth: bool = False

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
    def __init__(self, cfg: Config, progress: "ScanProgress | None" = None):
        self.cfg = cfg
        self.progress = progress
        log_sink = progress.log if progress and cfg.verbose else None
        self.client = HttpClient(
            timeout=cfg.timeout,
            verify=cfg.verify_tls,
            follow_redirects=cfg.follow_redirects,
            headers=cfg.headers,
            verbose=cfg.verbose,
            log_sink=log_sink,
            max_concurrency=cfg.max_concurrency,
            proxies=cfg.proxies,
            stealth=cfg.stealth,
        )
        self.crawler = Crawler(
            self.client,
            max_depth=cfg.max_depth,
            max_pages=cfg.max_pages,
            same_host_only=cfg.same_host_only,
            respect_robots=cfg.respect_robots,
            delay=cfg.delay,
            user_agent=cfg.headers.get("User-Agent", "Cinder/1.0"),
            on_page=progress.page_done if progress else None,
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

    async def check_directory_listing(self, url: str) -> None:
        resp = await self.client.get(url)
        if not resp or "html" not in resp.headers.get("content-type", "").lower():
            return
        soup = BeautifulSoup(resp.body, "lxml")
        title = soup.title.get_text(strip=True).lower() if soup.title else ""
        if title.startswith("index of"):
            self._add("directory_listing", "medium", url,
                      "Directory listing terbuka", resp, title[:200])

    def test_targets(self, pages: list[str]) -> list[str]:
        """Unique URLs to test: every discovered parameter of every crawled page."""
        targets: list[str] = []
        seen: set[str] = set()
        for page in pages:
            if page not in seen:
                seen.add(page)
                targets.append(page)
        return targets

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

    async def _run_module(self, name: str, factory: Callable[[], Awaitable[None]]) -> None:
        if self.progress:
            self.progress.module_start(name)
        try:
            await factory()
        finally:
            if self.progress:
                self.progress.module_done()

    def _payload_cb(self, name: str) -> Callable[[int, int], None] | None:
        if not self.progress:
            return None
        return lambda current, total: self.progress.set_payload_progress(name, current, total)

    def _check(self, name: str, coro_fn: Callable[[], Awaitable[list[Finding]]]):
        async def runner() -> None:
            for finding in await coro_fn():
                self._attach_evidence(finding)
        return name, runner

    def _build_plan(self, pages: list[str]) -> list[tuple[str, Callable[[], Awaitable[None]]]]:
        on = lambda name: self.cfg.checks.get(name, False)
        skip = self.cfg.params_to_skip
        targets = self.test_targets(pages)
        api_targets = self.crawler.api_targets
        plan: list[tuple[str, Callable[[], Awaitable[None]]]] = []
        check = self._check

        if on("headers"):
            plan.append(check("headers", lambda: modules.headers.run(self.client, self.report.target)))
        if on("directory_listing"):
            async def directory_listing() -> None:
                for page in pages:
                    await self.check_directory_listing(page)
            plan.append(("directory_listing", directory_listing))
        if on("sensitive_files"):
            plan.append(check("sensitive_files", lambda: modules.sensitive_files.run(self.client, self.report.target)))
        if on("xss"):
            plan.append(check("xss", lambda: modules.xss.run(self.client, targets, skip, progress_cb=self._payload_cb("xss"), api_targets=api_targets)))
        if on("sqli"):
            plan.append(check("sqli", lambda: modules.sqli.run(self.client, targets, skip, progress_cb=self._payload_cb("sqli"), api_targets=api_targets)))
        if on("open_redirect"):
            plan.append(check("open_redirect", lambda: modules.redirect.run(self.client, targets)))
        if on("traversal"):
            plan.append(check("traversal", lambda: modules.traversal.run(self.client, targets)))
        if on("jwt"):
            plan.append(check("jwt", lambda: modules.jwt.run(self.client, targets)))
        if on("idor"):
            plan.append(check("idor", lambda: modules.idor.run(self.client, targets)))
        if on("ssrf"):
            plan.append(check("ssrf", lambda: modules.ssrf.run(self.client, targets)))

        if self.cfg.deep:
            plan.extend(self._deep_plan(pages))
        if self.cfg.fuzz or self.cfg.fuzz_enabled:
            plan.append(check("fuzzer", lambda: modules.fuzzer.run(self.client, pages, progress_cb=self._payload_cb("fuzzer"))))
        if self.cfg.chain or self.cfg.chain_enabled:
            async def chain() -> None:
                for finding in modules.chain.run(self.report.findings):
                    self.report.add(finding)
            plan.append(("chain", chain))
        return plan

    def _deep_plan(self, pages: list[str]) -> list[tuple[str, Callable[[], Awaitable[None]]]]:
        root = self.report.target
        skip = self.cfg.params_to_skip
        plan: list[tuple[str, Callable[[], Awaitable[None]]]] = []
        check = self._check

        async def waf() -> None:
            name = await modules.waf.run(self.client, root)
            if name:
                self.report.add(Finding("waf", "info", root, f"WAF terdeteksi: {name}"))

        async def triage() -> None:
            self.report.findings = await modules.triage.run(self.client, self.report.findings, self.cfg)

        plan.extend([
            check("cmdi", lambda: modules.cmdi.run(self.client, pages, skip, progress_cb=self._payload_cb("cmdi"))),
            check("ssti", lambda: modules.ssti.run(self.client, pages, skip, progress_cb=self._payload_cb("ssti"))),
            check("deser", lambda: modules.deser.run(self.client, pages)),
            check("cors", lambda: modules.cors.run(self.client, pages)),
            check("csrf", lambda: modules.csrf.run(self.client, pages)),
            check("graphql", lambda: modules.graphql.run(self.client, root, progress_cb=self._payload_cb("graphql"))),
            check("cache", lambda: modules.cache.run(self.client, pages)),
            check("upload", lambda: modules.upload.run(self.client, pages, progress_cb=self._payload_cb("upload"))),
            check("logic", lambda: modules.logic.run(self.client, pages)),
            check("auth", lambda: modules.auth.run(self.client, pages)),
            check("race", lambda: modules.race.run(self.client, pages, progress_cb=self._payload_cb("race"))),
            check("smuggle", lambda: modules.smuggle.run(root, verbose=self.cfg.verbose)),
            check("domxss", lambda: modules.domxss.run(self.client, pages)),
            check("portscan", lambda: modules.portscan.run(root, progress_cb=self._payload_cb("portscan"))),
            check("server_audit", lambda: modules.server_audit.run(self.client, root)),
            check("templates", lambda: template_engine.run(self.client, pages)),
            ("waf", waf),
            ("triage", triage),
        ])
        return plan

    async def run(self, url: str) -> Report:
        if not self.cfg.checks:
            self.cfg.checks = {
                "headers": True, "xss": True, "sqli": True, "open_redirect": True,
                "directory_listing": True, "sensitive_files": True, "traversal": True,
                "jwt": True, "idor": True, "ssrf": True,
            }
        self.report.target = url
        if not self.progress:
            console.print(f"[cyan]→ Memindai[/] {url}")

        if self.cfg.login_url and self.cfg.username:
            await self.crawler.login(
                self.cfg.login_url,
                self.cfg.login_user_field,
                self.cfg.login_pass_field,
                self.cfg.username,
                self.cfg.password,
            )

        # FASE 1: crawl HTML
        if self.progress:
            self.progress.start_crawl(self.cfg.max_pages)
        pages = await self.crawler.crawl(url)
        pages = await self._seed_auth_pages(pages)
        if self.progress:
            self.progress.crawl_done(len(pages))
        else:
            console.print(f"[dim]  {len(pages)} halaman ditemukan (HTML)[/]")

        # FASE 1b: render JS (Playwright) — tambah URL dari DOM + XHR/fetch
        rendered = await self.crawler.render_js(url)
        if rendered and not self.progress:
            console.print(f"[dim]  {len(rendered)} URL dari render JS[/]")
        pages = self._merge(pages, rendered)

        xhr_urls = [item["url"] for item in self.crawler.xhr]
        if xhr_urls and not self.progress:
            console.print(f"[dim]  {len(xhr_urls)} endpoint XHR/fetch[/]")
        pages = self._merge(pages, xhr_urls)

        # FASE 3: endpoint dari JS + API schema
        if self.cfg.deep:
            js_findings, js_endpoints = await modules.jsrecon.run(self.client, pages)
            for finding in js_findings:
                self._attach_evidence(finding)
            schema_findings, schema_endpoints = await modules.apischema.run(self.client, url)
            for finding in schema_findings:
                self._attach_evidence(finding)
            pages = self._merge(pages, js_endpoints + schema_endpoints)

        # FASE 2: directory bruteforce
        if self.progress:
            self.progress.start_dirs(0)
        dir_findings, dir_urls = await modules.dir_fuzz.run(
            self.client,
            url,
            progress_cb=self.progress.dirs_progress if self.progress else None,
        )
        for finding in dir_findings:
            self._attach_evidence(finding)
        if self.progress:
            self.progress.dirs_done()
        elif dir_urls:
            console.print(f"[dim]  {len(dir_urls)} path dari directory fuzzing[/]")
        pages = self._merge(pages, dir_urls)

        # FASE 3b: parameter paksa untuk setiap URL tanpa query
        forced: list[str] = []
        for page in list(pages):
            if not urlparse(page).query:
                forced.extend(self.crawler.force_params(page))
        pages = self._merge(pages, forced)

        self.visited = pages
        self.report.pages_crawled = len(pages)
        if not self.progress:
            console.print(f"[dim]  total {len(pages)} URL target[/]")

        root = await self.client.get(url)
        if root:
            self.report.fingerprint = fingerprint(root)
            if self.report.fingerprint and not self.progress:
                console.print(f"[dim]  fingerprint: {self.report.fingerprint}[/]")

        # FASE 4: semua URL masuk ke modul vulnerability
        plan = self._build_plan(pages)
        if self.progress:
            self.progress.start_modules(len(plan))
        for name, factory in plan:
            await self._run_module(name, factory)
        return self.report

    @staticmethod
    def _merge(pages: list[str], extra: list[str]) -> list[str]:
        seen = set(pages)
        for item in extra:
            if item and item.startswith("http") and item not in seen:
                seen.add(item)
                pages.append(item)
        return pages


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
    table.add_column("CWE")
    table.add_column("URL", overflow="fold")
    table.add_column("Detail", overflow="fold")
    for f in report.findings:
        table.add_row(f"[{_severity_style(f.severity)}]{f.severity}[/]", f.check, f.cwe or "-", f.url, f.detail)
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
    sarif: bool = typer.Option(False, "--sarif", help="Keluarkan laporan format SARIF."),
    login_url: str | None = typer.Option(None, "--login-url", help="URL form login untuk sesi terautentikasi."),
    username: str | None = typer.Option(None, "--username", help="Username untuk login."),
    password: str | None = typer.Option(None, "--password", help="Password untuk login."),
    login_user_field: str = typer.Option("username", "--login-field-user", help="Nama field username di form login."),
    login_pass_field: str = typer.Option("password", "--login-field-pass", help="Nama field password di form login."),
    no_banner: bool = typer.Option(False, "--no-banner", help="Sembunyikan banner."),
    async_mode: bool = typer.Option(False, "--async", help="Mode async agresif: 100 request paralel, tanpa rate-limit."),
    proxy_list: Path | None = typer.Option(None, "--proxy-list", help="File berisi daftar proxy (satu per baris) untuk rotasi."),
    stealth: bool = typer.Option(False, "--stealth", help="Jeda acak 1-5 detik antar request (bypass rate-limit)."),
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

    if login_url:
        cfg.login_url = login_url
    if username:
        cfg.username = username
    if password:
        cfg.password = password
    cfg.login_user_field = login_user_field
    cfg.login_pass_field = login_pass_field

    if async_mode:
        cfg.async_mode = True
        cfg.max_concurrency = 100
        cfg.delay = 0

    cfg.stealth = stealth
    if proxy_list:
        if proxy_list.exists():
            cfg.proxies = [
                line.strip() for line in proxy_list.read_text().splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
        else:
            console.print(f"[yellow]Peringatan:[/] file proxy tidak ditemukan: {proxy_list}")

    if auth_token:
        token = auth_token if auth_token.lower().startswith("bearer ") else f"Bearer {auth_token}"
        cfg.headers["Authorization"] = token
    if cookie:
        cfg.headers["Cookie"] = cookie
    for raw_header in header:
        name, sep, value = raw_header.partition(":")
        if sep and name.strip():
            cfg.headers[name.strip()] = value.strip()

    async def _run(progress: ScanProgress) -> Report:
        scanner = Scanner(cfg, progress=progress)
        try:
            return await scanner.run(url)
        finally:
            await scanner.close()

    with ScanProgress(verbose=cfg.verbose) as progress:
        report = asyncio.run(_run(progress))
        progress.finish(len(report.findings))
    console.print(progress.summary())

    html_out = as_html or (output is not None and output.suffix.lower() in (".html", ".htm"))

    if sarif:
        if output:
            report.write_sarif(output)
            render_terminal(report)
            console.print(f"[green]✓[/] Laporan SARIF disimpan: {output}")
        else:
            console.print_json(data=report.to_sarif())
        if any(f.severity in ("high", "critical") for f in report.findings):
            raise typer.Exit(code=1)
        return

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
