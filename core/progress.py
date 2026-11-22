"""Live progress bars and status log for the scan."""
from __future__ import annotations

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
)

BAR_COLUMNS = [
    SpinnerColumn(style="bold #ff5f1f"),
    BarColumn(
        bar_width=32,
        style="grey23",
        complete_style="bold #ff5f1f",
        finished_style="bold #ff9d1f",
        pulse_style="bold #ff7a1f",
    ),
    TextColumn("[bold #ff9d1f]{task.percentage:>3.0f}%[/]"),
    TextColumn("[dim]{task.description}[/]"),
    TimeElapsedColumn(),
]


class ScanProgress:
    """Wraps a rich Progress: crawl bar, module bar, and a per-module spinner."""

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose
        self.console = Console(stderr=True)
        self.progress = Progress(*BAR_COLUMNS, console=self.console, transient=False)
        self.crawl_id: TaskID | None = None
        self.dirs_id: TaskID | None = None
        self.modules_id: TaskID | None = None
        self.spinner_id: TaskID | None = None
        self._pages = 0
        self._dirs = 0
        self._modules = 0
        self._findings = 0

    def __enter__(self) -> "ScanProgress":
        self.progress.start()
        self.crawl_id = self.progress.add_task("Crawling", total=None)
        self.dirs_id = self.progress.add_task("Fuzzing Directories...", total=None, visible=False)
        self.modules_id = self.progress.add_task("Scanning modules", total=None)
        self.spinner_id = self.progress.add_task("Menunggu", total=None)
        self.progress.update(self.spinner_id, visible=False)
        return self

    def __exit__(self, *exc) -> None:
        self.progress.stop()

    def log(self, message: str) -> None:
        self.console.log(message, highlight=False)

    def start_crawl(self, total: int) -> None:
        if self.crawl_id is not None:
            self.progress.update(self.crawl_id, total=total, completed=0)

    def page_done(self) -> None:
        self._pages += 1
        if self.crawl_id is not None:
            self.progress.advance(self.crawl_id)

    def crawl_done(self, pages: int) -> None:
        self._pages = pages
        if self.crawl_id is not None:
            self.progress.update(self.crawl_id, total=pages or 1, completed=pages, visible=False)

    def start_dirs(self, total: int) -> None:
        if self.dirs_id is not None:
            self.progress.update(self.dirs_id, total=total, completed=0, visible=True)

    def dirs_progress(self, current: int, total: int) -> None:
        self._dirs = current
        if self.dirs_id is not None:
            self.progress.update(
                self.dirs_id, total=total, completed=current,
                description=f"Fuzzing Directories... {current}/{total}", refresh=True,
            )

    def dirs_done(self) -> None:
        if self.dirs_id is not None:
            self.progress.update(self.dirs_id, visible=False)

    def start_modules(self, total: int) -> None:
        if self.modules_id is not None:
            self.progress.update(self.modules_id, total=total, completed=0)

    def module_start(self, name: str, payloads: int = 0) -> None:
        if self.spinner_id is not None:
            label = f"Testing {name}"
            if payloads:
                label += f" — {payloads} payloads"
            self.progress.update(self.spinner_id, description=label, visible=True)

    def set_payload_progress(self, name: str, current: int, total: int) -> None:
        if self.spinner_id is not None:
            self.progress.update(
                self.spinner_id,
                description=f"Testing {name} — {current}/{total} payloads",
                refresh=True,
            )

    def module_done(self) -> None:
        self._modules += 1
        if self.modules_id is not None:
            self.progress.advance(self.modules_id)
        if self.spinner_id is not None:
            self.progress.update(self.spinner_id, visible=False)

    def finish(self, findings: int) -> None:
        self._findings = findings
        for task in (self.crawl_id, self.dirs_id, self.modules_id, self.spinner_id):
            if task is not None:
                self.progress.update(task, visible=False)

    def summary(self) -> str:
        return (
            f"[bold green]✓[/] Crawling [bold]{self._pages}[/] halaman · "
            f"[bold green]✓[/] [bold]{self._dirs}[/] dirs · "
            f"[bold green]✓[/] [bold]{self._modules}[/] modul · "
            f"[bold green]✓[/] [bold]{self._findings}[/] temuan"
        )
