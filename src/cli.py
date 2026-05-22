#!/usr/bin/env python3
"""
SatScan CLI - Satellite Telemetry & Link Security Auditor
AI-enhanced CCSDS TM/TC analysis for Starshield / NRO / LEO operations.
"""

import json
import sys
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from src.config import SatScanConfig
from src.parser.ccsds_parser import CCSDSParser, ParsedPacket
from src.checks.base import SecurityCheckEngine
from src.ai.ollama_client import SatScanAI
from src.reporter import ReportGenerator

app = typer.Typer(
    name="satscan",
    help="SatScan - Intelligent Satellite Cybersecurity Auditor",
    rich_help_panel=True,
    add_completion=True,
)

console = Console()
config = SatScanConfig()


@app.command()
def parse(
    file_path: Path = typer.Argument(..., help="Path to binary, .pcap, or raw CCSDS file"),
    output: str = typer.Option("json", help="Output format: json, table, quiet"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """Parse CCSDS TM/TC packets from file."""
    try:
        parser = CCSDSParser()
        packets: List[ParsedPacket] = parser.parse_file(file_path)

        if verbose:
            rprint(f"[bold green]Parsed {len(packets)} packets from {file_path}[/]")

        if output == "json":
            data = [pkt.model_dump() for pkt in packets]
            typer.echo(json.dumps(data, indent=2, default=str))
        elif output == "table":
            _print_packet_table(packets)
        else:
            typer.echo(f"Parsed {len(packets)} packets.")

    except Exception as e:
        console.print(f"[bold red]Error parsing file:[/] {e}", style="red")
        raise typer.Exit(code=1)


@app.command()
def scan(
    file_path: Path = typer.Argument(..., help="File to scan"),
    ai: bool = typer.Option(False, "--ai", help="Enable AI explanations"),
    agent: Optional[str] = typer.Option(None, "--agent", help="Run agentic investigation with prompt"),
    ml: bool = typer.Option(False, "--ml", help="Enable ML anomaly detection"),
    output: str = typer.Option("html", help="Report format: json, html, pdf"),
    model: str = typer.Option("llama3.2", help="Ollama model to use"),
):
    """Full security scan with optional AI/ML enhancements."""
    try:
        # 1. Parse
        parser = CCSDSParser()
        packets = parser.parse_file(file_path)

        # 2. Run Security Checks
        check_engine = SecurityCheckEngine()
        findings = check_engine.run_all(packets)

        # 3. Optional ML Anomaly Detection
        if ml:
            from src.ai.ml_anomaly import run_ml_anomaly
            ml_findings = run_ml_anomaly(packets)
            findings.extend(ml_findings)

        # 4. Optional AI Layer
        ai_explanations = {}
        if ai or agent:
            ai_client = SatScanAI(model=model)
            for finding in findings:
                ai_explanations[finding["id"]] = ai_client.explain_finding(finding)

            if agent:
                agent_result = ai_client.run_agent(investigation_prompt=agent, findings=findings)
                rprint(f"\n[bold cyan]Agent Investigation Result:[/]\n{agent_result}")

        # 5. Generate Report
        reporter = ReportGenerator()
        report_path = reporter.generate(findings, packets, output_format=output, ai_explanations=ai_explanations)

        rprint(f"[bold green]Scan complete![/] Report saved to: {report_path}")

        # Summary Table
        _print_findings_summary(findings)

    except Exception as e:
        console.print(f"[bold red]Scan failed:[/] {e}", style="red")
        raise typer.Exit(code=1)


def _print_packet_table(packets: List[ParsedPacket]):
    """Pretty table for parsed packets."""
    table = Table(title="Parsed CCSDS Packets")
    table.add_column("SCID", justify="right")
    table.add_column("VCID/APID", justify="right")
    table.add_column("Seq Count", justify="right")
    table.add_column("Length", justify="right")
    table.add_column("Type", justify="center")

    for pkt in packets[:20]:  # Limit for display
        h = pkt.header
        pkt_type = "TC" if h.is_telecommand else "TM"
        table.add_row(
            str(h.scid),
            f"{h.vcid}/{h.apid}",
            str(h.sequence_count),
            str(h.packet_length),
            pkt_type
        )

    console.print(table)


def _print_findings_summary(findings: List[dict]):
    """Print rich summary of security findings."""
    if not findings:
        rprint("[bold green]No security findings detected.[/]")
        return

    table = Table(title="Security Findings Summary")
    table.add_column("Severity", style="red")
    table.add_column("Check", style="cyan")
    table.add_column("SPARTA ID", style="magenta")
    table.add_column("Description")

    for f in findings[:15]:
        table.add_row(
            f.get("severity", "LOW"),
            f.get("check_type", "Unknown"),
            f.get("sparta_id", "N/A"),
            f.get("description", "")[:80] + "..." if len(f.get("description", "")) > 80 else f.get("description", "")
        )

    console.print(table)


@app.command()
def version():
    """Show SatScan version and configuration."""
    rprint(f"[bold]SatScan v{config.version}[/]")
    rprint(f"AI Support: {'Enabled' if config.ai_enabled else 'Disabled'}")
    rprint(f"Default Model: {config.default_model}")


if __name__ == "__main__":
    app()
