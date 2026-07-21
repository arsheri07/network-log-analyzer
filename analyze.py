"""
analyze.py
----------
Main entry point. Parses the log, runs every detection rule, and
prints a clean severity-sorted report to the terminal.

Run: python3 analyze.py
"""

from parser import parse_log_file
from rules import brute_force_detector, odd_hours_detector, slow_brute_force_detector

from rich.console import Console
from rich.table import Table

console = Console()

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
SEVERITY_COLOR = {"HIGH": "bold red", "MEDIUM": "yellow", "LOW": "dim"}


def main():
    console.print("\n[bold]Network Log Analyzer[/bold]")
    console.print("Parsing sample_auth.log...\n")

    events = parse_log_file("sample_auth.log")
    console.print(f"Loaded [bold]{len(events)}[/bold] login events\n")

    findings = []
    findings += brute_force_detector(events)
    findings += odd_hours_detector(events)
    findings += slow_brute_force_detector(events)

    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])

    if not findings:
        console.print("\n[green]No suspicious activity detected.[/green]")
        return

    table = Table(title="\nSecurity Findings", show_lines=True)
    table.add_column("Severity", style="bold")
    table.add_column("Rule")
    table.add_column("Source IP")
    table.add_column("Detail")

    for f in findings:
        table.add_row(
            f"[{SEVERITY_COLOR[f.severity]}]{f.severity}[/{SEVERITY_COLOR[f.severity]}]",
            f.rule,
            f.ip,
            f.detail,
        )

    console.print(table)
    console.print(f"\n[bold]{len(findings)}[/bold] finding(s) total\n")


if __name__ == "__main__":
    main()
