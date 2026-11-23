"""Finding collection and JSON/HTML report generation."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

DEFAULT_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "report"


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

    def render_html(self, template_dir: Path = DEFAULT_TEMPLATE_DIR) -> str:
        env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        template = env.get_template("template.html")
        return template.render(report=self.to_dict())

    def write_html(self, path: Path, template_dir: Path = DEFAULT_TEMPLATE_DIR) -> None:
        path.write_text(self.render_html(template_dir), encoding="utf-8")
