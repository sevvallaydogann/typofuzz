#!/usr/bin/env python3
"""
╔════════════════════════════════════════════════════════════╗
║          TYPOSQUATCH - Typosquatting Domain Hunter         ║
║              OSINT / Threat Intelligence Tool              ║
╚════════════════════════════════════════════════════════════╝
  
"""

import argparse
import sys
import time
import json
import csv
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.text import Text
from rich.columns import Columns
from rich import box
from rich.style import Style

from generators import DomainGenerator
from dns_check import DNSChecker
from whois_check import WHOISChecker
from http_check import HTTPChecker
from ssl_check import SSLChecker
from threat_intel import ThreatIntelChecker
from risk_scorer import RiskScorer
from reporter import Reporter

console = Console()

BANNER = """
[bold red]
 ████████╗██╗   ██╗██████╗  ██████╗ ███████╗ ██████╗ ██╗   ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
    ██╔══╝╚██╗ ██╔╝██╔══██╗██╔═══██╗██╔════╝██╔═══██╗██║   ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
    ██║    ╚████╔╝ ██████╔╝██║   ██║███████╗██║   ██║██║   ██║███████║   ██║   ██║     ███████║
    ██║     ╚██╔╝  ██╔═══╝ ██║   ██║╚════██║██║▄▄ ██║██║   ██║██╔══██║   ██║   ██║     ██╔══██║
    ██║      ██║   ██║     ╚██████╔╝███████║╚██████╔╝╚██████╔╝██║  ██║   ██║   ╚██████╗██║  ██║
    ╚═╝      ╚═╝   ╚═╝      ╚═════╝ ╚══════╝ ╚══▀▀═╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
[/bold red]
[bold yellow]                    🎯 Typosquatting Domain Hunter & OSINT Tool v1.0.0[/bold yellow]
[dim]                            Phishing domain detection & threat intelligence[/dim]
"""


def print_banner():
    console.print(BANNER)
    console.print(
        Panel(
            "[bold white]⚠  LEGAL DISCLAIMER:[/bold white] This tool is designed solely for [bold green]authorized security testing[/bold green] and "
            "[bold green]defensive threat intelligence[/bold green].\n"
            "   Unauthorized use is illegal. The user assumes all responsibility.",
            style="bold yellow",
            border_style="yellow",
            padding=(0, 2),
        )
    )
    console.print()


def print_stats(results: list[dict]):
    total = len(results)
    registered = sum(1 for r in results if r.get("registered"))
    active_http = sum(1 for r in results if r.get("http_status") and r["http_status"] < 400)
    has_mx = sum(1 for r in results if r.get("mx_records"))
    has_ssl = sum(1 for r in results if r.get("ssl_valid"))
    high_risk = sum(1 for r in results if r.get("risk_score", 0) >= 70)
    med_risk = sum(1 for r in results if 40 <= r.get("risk_score", 0) < 70)

    stats = [
        Panel(f"[bold white]{total}[/bold white]\n[dim]Total Variations[/dim]", border_style="blue", padding=(0, 2)),
        Panel(f"[bold red]{registered}[/bold red]\n[dim]Registered Domains[/dim]", border_style="red", padding=(0, 2)),
        Panel(f"[bold yellow]{active_http}[/bold yellow]\n[dim]Active Websites[/dim]", border_style="yellow", padding=(0, 2)),
        Panel(f"[bold cyan]{has_mx}[/bold cyan]\n[dim]Has MX Record[/dim]", border_style="cyan", padding=(0, 2)),
        Panel(f"[bold magenta]{has_ssl}[/bold magenta]\n[dim]SSL Certificate[/dim]", border_style="magenta", padding=(0, 2)),
        Panel(f"[bold red]{high_risk}[/bold red]\n[dim]High Risk[/dim]", border_style="bright_red", padding=(0, 2)),
    ]
    console.print(Columns(stats))
    console.print()


def build_results_table(results: list[dict], show_all: bool = False) -> Table:
    table = Table(
        title="🔍 Typosquatting Analysis Results",
        box=box.ROUNDED,
        border_style="bold blue",
        header_style="bold white on dark_blue",
        show_lines=True,
        padding=(0, 1),
    )

    table.add_column("Domain", style="bold cyan", min_width=30)
    table.add_column("Type", style="dim", min_width=16)
    table.add_column("Registered", justify="center", min_width=8)
    table.add_column("HTTP", justify="center", min_width=6)
    table.add_column("MX", justify="center", min_width=5)
    table.add_column("SSL", justify="center", min_width=5)
    table.add_column("IP", style="dim", min_width=15)
    table.add_column("Threat Intel", justify="center", min_width=12)
    table.add_column("Risk", justify="center", min_width=8)

    def risk_style(score):
        if score >= 70:
            return f"[bold red]{score}[/bold red] 🔴"
        elif score >= 40:
            return f"[bold yellow]{score}[/bold yellow] 🟡"
        elif score >= 10:
            return f"[bold green]{score}[/bold green] 🟢"
        else:
            return f"[dim]{score}[/dim] ⚪"

    def http_style(status):
        if status is None:
            return "[dim]-[/dim]"
        if status < 300:
            return f"[green]{status}[/green]"
        elif status < 400:
            return f"[yellow]{status}[/yellow]"
        else:
            return f"[red]{status}[/red]"

    filtered = results if show_all else [r for r in results if r.get("registered")]

    for r in sorted(filtered, key=lambda x: x.get("risk_score", 0), reverse=True):
        table.add_row(
            r.get("domain", ""),
            r.get("variation_type", ""),
            "✅" if r.get("registered") else "❌",
            http_style(r.get("http_status")),
            "✅" if r.get("mx_records") else "❌",
            "✅" if r.get("ssl_valid") else "❌",
            r.get("ip_address", "-") or "-",
            "⚠️ THREAT" if r.get("is_threat") else ("[green]Clean[/green]" if r.get("registered") else "[dim]-[/dim]"),
            risk_style(r.get("risk_score", 0)),
        )

    return table


def analyze_domain(domain: str, config: dict) -> dict:
    """Analyze a single domain variation."""
    result = domain.copy() if isinstance(domain, dict) else {"domain": domain, "variation_type": "unknown"}
    target = result["domain"]

    # DNS Check
    dns_checker = DNSChecker()
    dns_info = dns_checker.check(target)
    result.update(dns_info)

    if result.get("registered"):
        # HTTP Check
        if config.get("http_check", True):
            http_checker = HTTPChecker()
            http_info = http_checker.check(target)
            result.update(http_info)

        # SSL Check
        if config.get("ssl_check", True):
            ssl_checker = SSLChecker()
            ssl_info = ssl_checker.check(target)
            result.update(ssl_info)

        # WHOIS Check
        if config.get("whois_check", True):
            whois_checker = WHOISChecker()
            whois_info = whois_checker.check(target)
            result.update(whois_info)

        # Threat Intel
        if config.get("threat_intel", True):
            intel_checker = ThreatIntelChecker(
                vt_api_key=config.get("vt_api_key"),
            )
            intel_info = intel_checker.check(target)
            result.update(intel_info)

    # Risk Score
    scorer = RiskScorer()
    result["risk_score"] = scorer.score(result)

    return result


def run_scan(target_domain: str, args: argparse.Namespace) -> list[dict]:
    config = {
        "http_check": not args.no_http,
        "ssl_check": not args.no_ssl,
        "whois_check": not args.no_whois,
        "threat_intel": not args.no_intel,
        "vt_api_key": args.vt_key,
        "threads": args.threads,
    }

    # Generate variations
    console.print(f"\n[bold cyan]⚙  Generating domain variations:[/bold cyan] [bold white]{target_domain}[/bold white]")
    generator = DomainGenerator(target_domain)
    variations = generator.generate(
        homoglyphs=not args.no_homoglyphs,
        typos=not args.no_typos,
        tld=not args.no_tld,
        subdomains=not args.no_subdomains,
        bitsquatting=args.bitsquatting,
        combosquatting=args.combosquatting,
        extra_keywords=args.keywords.split(",") if args.keywords else [],
    )

    console.print(f"[bold green]✓[/bold green] [bold white]{len(variations)}[/bold white] variations generated.\n")

    results = []
    with Progress(
        SpinnerColumn(style="bold cyan"),
        TextColumn("[bold white]{task.description}"),
        BarColumn(bar_width=40, style="cyan", complete_style="bold green"),
        TextColumn("[bold white]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("[cyan]Scanning domains...", total=len(variations))

        with ThreadPoolExecutor(max_workers=config["threads"]) as executor:
            futures = {
                executor.submit(analyze_domain, v, config): v
                for v in variations
            }
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=30)
                    results.append(result)
                    domain = result.get("domain", "")
                    registered = result.get("registered", False)
                    risk = result.get("risk_score", 0)
                    if registered:
                        style = "bold red" if risk >= 70 else "bold yellow" if risk >= 40 else "bold green"
                        progress.console.print(
                            f"  [bold green]●[/bold green] [cyan]{domain:<40}[/cyan] "
                            f"[{style}]Risk: {risk:>3}[/{style}] "
                            f"{'[red]⚠ REGISTERED[/red]' if registered else ''}"
                        )
                except Exception as e:
                    v = futures[future]
                    results.append({
                        "domain": v.get("domain", str(v)),
                        "variation_type": v.get("variation_type", "unknown"),
                        "error": str(e),
                        "risk_score": 0,
                        "registered": False,
                    })
                progress.advance(task)

    return results


def main():
    parser = argparse.ArgumentParser(
        prog="typosquatch",
        description="🎯 Typosquatch - Typosquatting Domain Hunter & OSINT Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python typosquatch.py google.com
  python typosquatch.py paypal.com --threads 20 --output html
  python typosquatch.py example.com --vt-key YOUR_KEY --bitsquatting --keywords login,secure,bank
  python typosquatch.py mybank.com --no-intel --output json,csv --show-all
        """
    )

    parser.add_argument("domain", help="Target domain (e.g., google.com)")
    parser.add_argument("-t", "--threads", type=int, default=10, metavar="N",
                        help="Number of parallel threads (default: 10)")
    parser.add_argument("-o", "--output", default="html", metavar="FORMAT",
                        help="Output format: html,json,csv (default: html)")
    parser.add_argument("--output-dir", default="reports", metavar="DIR",
                        help="Report output directory (default: reports/)")
    parser.add_argument("--vt-key", metavar="KEY",
                        help="VirusTotal API key")
    parser.add_argument("--keywords", metavar="KW1,KW2",
                        help="Additional keywords for combosquatting (comma-separated)")
    parser.add_argument("--show-all", action="store_true",
                        help="Show unregistered domains in the table as well")
    parser.add_argument("--bitsquatting", action="store_true",
                        help="Include bitsquatting variations")
    parser.add_argument("--combosquatting", action="store_true",
                        help="Include combosquatting variations")

    # Disable flags
    parser.add_argument("--no-http", action="store_true", help="Skip HTTP check")
    parser.add_argument("--no-ssl", action="store_true", help="Skip SSL check")
    parser.add_argument("--no-whois", action="store_true", help="Skip WHOIS check")
    parser.add_argument("--no-intel", action="store_true", help="Skip threat intelligence")
    parser.add_argument("--no-homoglyphs", action="store_true", help="Skip homoglyph variations")
    parser.add_argument("--no-typos", action="store_true", help="Skip typo variations")
    parser.add_argument("--no-tld", action="store_true", help="Skip TLD variations")
    parser.add_argument("--no-subdomains", action="store_true", help="Skip subdomain variations")

    args = parser.parse_args()

    print_banner()

    start_time = datetime.now()

    # Run scan
    results = run_scan(args.domain, args)

    console.print()
    console.rule("[bold cyan]📊 SCAN RESULTS[/bold cyan]")
    console.print()

    print_stats(results)

    table = build_results_table(results, show_all=args.show_all)
    console.print(table)

    # Output reports
    # os.makedirs(args.output_dir, exist_ok=True)
    reporter = Reporter(args.domain, results)

    output_formats = [f.strip().lower() for f in args.output.split(",")]
    generated_files = []

    for fmt in output_formats:
        if fmt == "html":
            path = reporter.to_html()
            generated_files.append(("HTML Report", path))
        elif fmt == "json":
            path = reporter.to_json()
            generated_files.append(("JSON Data", path))
        elif fmt == "csv":
            path = reporter.to_csv()
            generated_files.append(("CSV Data", path))

    elapsed = (datetime.now() - start_time).total_seconds()

    console.print()
    console.print(Panel(
        "\n".join([
            f"[bold green]✓ Scan completed![/bold green]  ⏱  {elapsed:.1f} seconds",
            "",
            *[f"  📄 [bold white]{label}:[/bold white] [cyan]{path}[/cyan]" for label, path in generated_files],
        ]),
        title="[bold green]✅ COMPLETED[/bold green]",
        border_style="green",
        padding=(1, 2),
    ))


if __name__ == "__main__":
    main()