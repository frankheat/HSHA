from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from .models import (
    HeaderResult, Severity,
    SEVERITY_COLORS, SEVERITY_LABELS, SEVERITY_SYMBOLS,
)

console = Console()


def report(results: list[HeaderResult]) -> None:
    _print_banner()
    _print_table(results)
    _print_findings(results)
    _print_summary(results)


# ---------------------------------------------------------------------------
# Shared
# ---------------------------------------------------------------------------

def _print_banner():
    console.print()
    console.print(Panel.fit(
        "[bold white]HSHA[/bold white] [dim]— HTTP Security Header Analyzer[/dim]",
        border_style="bright_blue",
    ))
    console.print()


def _val_display(r: HeaderResult) -> str | Text:
    if r.value is None:
        return Text("— not present —", style="dim italic")
    if r.value.strip() == '':
        return Text("— empty —", style="dim italic yellow")
    return r.value


def _print_table(results: list[HeaderResult]):
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white", expand=False)
    table.add_column("Header", min_width=38, no_wrap=True)
    table.add_column("Severity", min_width=12, no_wrap=True)
    table.add_column("Value", overflow="fold")

    for r in results:
        sev = r.worst_severity
        # '?' rather than the severity symbol: the level is what it is worth if it
        # applies, and nothing settled has reached it.
        symbol = "?" if r.is_contingent else SEVERITY_SYMBOLS[sev]
        status = Text(f"{symbol} {SEVERITY_LABELS[sev]}", style=SEVERITY_COLORS[sev])
        table.add_row(r.canonical_name, status, _val_display(r))

    console.print(table)
    console.print()


def _print_finding(f):
    color = SEVERITY_COLORS[f.severity]
    label = SEVERITY_LABELS[f.severity]
    console.print(f"  [{color}][{label}][/{color}] [bold]{f.title}[/bold]")
    if f.description:
        console.print(f"        [dim]{f.description}[/dim]")
    if f.recommendation:
        console.print(f"        [italic]→ {f.recommendation}[/italic]")
    if f.verify:
        console.print(f"        [yellow]?[/yellow] [italic]{f.verify}[/italic]")


def _print_group(title: str, subtitle: str, groups):
    console.print(f"[bold]{title}[/bold] [dim]{subtitle}[/dim]")
    console.print()
    for result, findings in groups:
        console.print(f"[bold underline]{result.canonical_name}[/bold underline]")
        if result.value:
            console.print(f"  [dim]Value:[/dim] {result.value}")
        for f in findings:
            _print_finding(f)
        console.print()


def _print_findings(results: list[HeaderResult]):
    def group(predicate):
        pairs = [(r, [f for f in r.findings if f.severity > Severity.OK and predicate(f)])
                 for r in results]
        return [(r, fs) for r, fs in pairs if fs]

    settled = group(lambda f: not f.is_contingent)
    contingent = group(lambda f: f.is_contingent)

    if not settled and not contingent:
        console.print("[green]No issues found.[/green]")
        console.print()
        return

    if settled:
        _print_group("Findings", "(the response settles these)", settled)

    if contingent:
        _print_group(
            "To confirm",
            "(what these are worth depends on something the response cannot say)",
            contingent,
        )


def _tally(findings) -> str:
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    parts = [
        f"[{SEVERITY_COLORS[sev]}]{counts[sev]} {SEVERITY_LABELS[sev]}[/{SEVERITY_COLORS[sev]}]"
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                    Severity.LOW, Severity.INFO, Severity.NOTE)
        if counts[sev]
    ]
    return "  ".join(parts) if parts else "[green]none[/green]"


def _print_summary(results: list[HeaderResult]):
    all_findings = [f for r in results for f in r.findings]

    worst = max((f.severity for f in all_findings), default=Severity.OK)
    worst_color = SEVERITY_COLORS[worst]

    present = sum(1 for r in results if r.is_present)
    missing = sum(1 for r in results if not r.is_present)

    # Kept apart because they are not the same claim: one is what the response
    # shows, the other is what it would be worth once someone has checked.
    body = (
        f"[bold]Checked:[/bold] {len(results)}   "
        f"[bold]Present:[/bold] [green]{present}[/green]   "
        f"[bold]Missing:[/bold] [red]{missing}[/red]\n"
        f"[bold]Settled:[/bold]     "
        + _tally([f for f in all_findings if not f.is_contingent]) + "\n"
        f"[bold]To confirm:[/bold]  "
        + _tally([f for f in all_findings if f.is_contingent])
    )

    console.print(Panel(
        body,
        title=f"[{worst_color}]Overall: {SEVERITY_LABELS[worst]}[/{worst_color}]",
        border_style=worst_color,
    ))
    console.print()
