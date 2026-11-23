"""Cinder CLI banner."""
from __future__ import annotations

from rich.console import Console
from rich.text import Text

LOGO = [
    " ██████╗██╗███╗   ██╗██████╗ ███████╗██████╗ ",
    "██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗",
    "██║     ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝",
    "██║     ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗",
    "╚██████╗██║██║ ╚████║██████╔╝███████╗██║  ██║",
    " ╚═════╝╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝",
]

GRADIENT = ["#ff1f1f", "#ff4d1f", "#ff7a1f", "#ff9d1f", "#ffb62e", "#ffc94d"]


def show_banner(console: Console | None = None) -> None:
    console = console or Console()
    width = max(len(line) for line in LOGO)
    for index, line in enumerate(LOGO):
        color = GRADIENT[index % len(GRADIENT)]
        console.print(Text(line.ljust(width), style=f"bold {color}"))
    console.print(Text("  Web Vulnerability Scanner  ", style="dim"))
    console.print(Text("  by lifyDev  ", style="bold cyan"))
    console.print(Text("  v0.3  ", style="dim grey50"))
    console.print(Text("─" * 60, style="dim"))
    console.print()
