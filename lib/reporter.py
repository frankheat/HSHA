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


def report(
    results: list[HeaderResult],
    mode: str = 'severity',   # 'severity' | 'simple'
) -> None:
    if mode == 'list':
        _print_list(results)
        return
    _print_banner()
    if mode == 'simple':
        _print_table_simple(results)
        _print_findings_simple(results)
        _print_summary_simple(results)
    else:
        _print_table_severity(results)
        _print_findings_severity(results)
        _print_summary_severity(results)


# ---------------------------------------------------------------------------
# Shared
# ---------------------------------------------------------------------------

_CONTEXT_NOTE = (
    "[yellow]Note:[/yellow] [dim]This analysis is context-unaware. "
    "Some findings may not apply depending on the type of endpoint "
    "(HTML page, API, static asset, file download). "
    "Review results accordingly.[/dim]"
)


def _print_banner():
    console.print()
    console.print(Panel.fit(
        "[bold white]HSHA[/bold white] [dim]— HTTP Security Header Analyzer — OWASP-based[/dim]",
        border_style="bright_blue",
    ))
    console.print(_CONTEXT_NOTE)
    console.print()


def _val_display(r: HeaderResult) -> str | Text:
    if r.value is None:
        return Text("— not present —", style="dim italic")
    if r.value.strip() == '':
        return Text("— empty —", style="dim italic yellow")
    return r.value


def _is_issue(r: HeaderResult) -> bool:
    return any(f.severity > Severity.OK for f in r.findings)


# ---------------------------------------------------------------------------
# Severity mode
# ---------------------------------------------------------------------------

def _print_table_severity(results: list[HeaderResult]):
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white", expand=False)
    table.add_column("Header", min_width=38, no_wrap=True)
    table.add_column("Severity", min_width=12, no_wrap=True)
    table.add_column("Value", overflow="fold")

    for r in results:
        sev = r.worst_severity
        status = Text(f"{SEVERITY_SYMBOLS[sev]} {SEVERITY_LABELS[sev]}", style=SEVERITY_COLORS[sev])
        table.add_row(r.canonical_name, status, _val_display(r))

    console.print(table)
    console.print()


def _print_findings_severity(results: list[HeaderResult]):
    interesting = [
        (r, [f for f in r.findings if f.severity > Severity.OK])
        for r in results
    ]
    interesting = [(r, fs) for r, fs in interesting if fs]

    if not interesting:
        console.print("[green]No issues found.[/green]")
        console.print()
        return

    console.print("[bold]Findings[/bold]")
    console.print()

    for result, findings in interesting:
        console.print(f"[bold underline]{result.canonical_name}[/bold underline]")
        if result.value:
            console.print(f"  [dim]Value:[/dim] {result.value}")

        for f in findings:
            color = SEVERITY_COLORS[f.severity]
            label = SEVERITY_LABELS[f.severity]
            console.print(f"  [{color}][{label}][/{color}] [bold]{f.title}[/bold]")
            if f.description:
                console.print(f"        [dim]{f.description}[/dim]")
            if f.recommendation:
                console.print(f"        [italic]→ {f.recommendation}[/italic]")

        console.print()


def _print_summary_severity(results: list[HeaderResult]):
    all_findings = [f for r in results for f in r.findings]
    counts = {s: 0 for s in Severity}
    for f in all_findings:
        counts[f.severity] += 1

    worst = max((f.severity for f in all_findings), default=Severity.OK)
    worst_color = SEVERITY_COLORS[worst]

    parts = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        if counts[sev]:
            c = SEVERITY_COLORS[sev]
            parts.append(f"[{c}]{counts[sev]} {SEVERITY_LABELS[sev]}[/{c}]")

    present = sum(1 for r in results if r.is_present)
    missing = sum(1 for r in results if not r.is_present)

    body = (
        f"[bold]Checked:[/bold] {len(results)}   "
        f"[bold]Present:[/bold] [green]{present}[/green]   "
        f"[bold]Missing:[/bold] [red]{missing}[/red]\n"
        f"[bold]Issues:[/bold]  " + ("  ".join(parts) if parts else "[green]none[/green]")
    )

    console.print(Panel(
        body,
        title=f"[{worst_color}]Overall: {SEVERITY_LABELS[worst]}[/{worst_color}]",
        border_style=worst_color,
    ))
    console.print()


# ---------------------------------------------------------------------------
# Simple mode
# ---------------------------------------------------------------------------

def _print_table_simple(results: list[HeaderResult]):
    table = Table(box=box.ROUNDED, show_header=True, header_style="bold white", expand=False)
    table.add_column("Header", min_width=38, no_wrap=True)
    table.add_column("Result", min_width=8, no_wrap=True)
    table.add_column("Value", overflow="fold")

    for r in results:
        status = Text("✗ FAIL", style="red") if _is_issue(r) else Text("✓ PASS", style="green")
        table.add_row(r.canonical_name, status, _val_display(r))

    console.print(table)
    console.print()


def _print_findings_simple(results: list[HeaderResult]):
    issues = [(r, [f for f in r.findings if f.severity > Severity.OK]) for r in results]
    issues = [(r, fs) for r, fs in issues if fs]

    if not issues:
        console.print("[green]No issues found.[/green]")
        console.print()
        return

    console.print("[bold]Issues[/bold]")
    console.print()

    for result, findings in issues:
        console.print(f"[bold underline]{result.canonical_name}[/bold underline]")
        if result.value:
            console.print(f"  [dim]Value:[/dim] {result.value}")

        for f in findings:
            console.print(f"  [red]✗[/red] {f.title}")
            if f.description:
                console.print(f"      [dim]{f.description}[/dim]")
            if f.recommendation:
                console.print(f"      [italic]→ {f.recommendation}[/italic]")

        console.print()


def _print_summary_simple(results: list[HeaderResult]):
    total = len(results)
    failed = sum(1 for r in results if _is_issue(r))
    passed = total - failed
    missing = sum(1 for r in results if not r.is_present)

    if failed == 0:
        color, label = "green", "PASS"
    else:
        color, label = "red", "FAIL"

    body = (
        f"[bold]Checked:[/bold] {total}   "
        f"[bold]Present:[/bold] [green]{total - missing}[/green]   "
        f"[bold]Missing:[/bold] [red]{missing}[/red]\n"
        f"[bold]Passed:[/bold]  [green]{passed}[/green]   "
        f"[bold]Failed:[/bold]  [red]{failed}[/red]"
    )

    console.print(Panel(body, title=f"[{color}]Overall: {label}[/{color}]", border_style=color))
    console.print()


def _print_list(results: list[HeaderResult]):
    failed = [r for r in results if _is_issue(r)]
    if not failed:
        console.print("[green]No issues found.[/green]")
        return
    console.print("The following headers are missing or misconfigured:")
    console.print()
    for r in failed:
        console.print(f"  {r.canonical_name}")
