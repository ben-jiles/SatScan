#!/usr/bin/env python3
"""
SatScan CLI - Satellite Telemetry & Link Security Auditor
"""

import json
import sys
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.table import Table

from src.config import SatScanConfig
from src.parser.ccsds_parser import CCSDSParser
from src.checks.engine import SecurityCheckEngine
from src.ai.explainers import enrich_findings_with_ai
from src.ai.agent import SatScanAgent
from src.reporter import ReportGenerator

app = typer.Typer(name="satscan", help="SatScan - Intelligent Satellite Cybersecurity Auditor")
console = Console()
config = SatScanConfig()


@app.command()
def parse(
    file_path: Path = typer.Argument(..., help="Path to binary, .pcap, or raw CCSDS file"),
    output: str = typer.Option("table", help="Output format: json, table"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
):
    """Parse CCSDS packets only."""
    try:
        parser = CCSDSParser()
        packets = parser.parse_file(file_path)
        
        if verbose or output == "table":
            _print_packet_table(packets)
        if output == "json":
            typer.echo(json.dumps([p.model_dump() for p in packets], indent=2, default=str))
        else:
            typer.echo(f"Parsed {len(packets)} packets.")
    except Exception as e:
        console.print(f"[red]Parse error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def scan(
    file_path: Path = typer.Argument(..., help="File to scan"),
    ai: bool = typer.Option(False, "--ai", help="Enable AI explanations"),
    agent: Optional[str] = typer.Option(None, "--agent", help="Agent investigation prompt"),
    ml: bool = typer.Option(False, "--ml", help="Enable ML anomaly detection"),
    output: str = typer.Option("html", help="Report format: json, html, pdf"),
    model: str = typer.Option("llama3.2", help="Ollama model"),
):
    """Full security scan with AI/ML."""
    try:
        parser = CCSDSParser()
        packets = parser.parse_file(file_path)

        engine = SecurityCheckEngine(enable_ml=ml)
        findings = engine.run_all(packets)

        if ai or agent:
            findings = enrich_findings_with_ai(findings, model=model)

        if agent:
            agent_obj = SatScanAgent(model=model)
            result = agent_obj.investigate(agent, findings, len(packets))
            console.print(f"\n[bold cyan]Agent Analysis:[/]\n{result}\n")

        reporter = ReportGenerator()
        report_path = reporter.generate(
            findings=findings,
            packets=packets,
            output_format=output,
            scan_file=str(file_path)
        )

        console.print(f"[bold green]Scan complete![/] Report: {report_path}")
        _print_findings_summary(findings)

    except Exception as e:
        console.print(f"[bold red]Scan failed:[/] {e}")
        raise typer.Exit(1)


def _print_packet_table(packets):
    table = Table(title="Parsed CCSDS Packets")
    table.add_column("SCID")
    table.add_column("VCID")
    table.add_column("APID")
    table.add_column("Seq")
    table.add_column("Length")
    for p in packets[:15]:
        h = p.header
        table.add_row(str(h.scid), str(h.vcid), str(h.apid), str(h.sequence_count), str(h.packet_length))
    console.print(table)


def _print_findings_summary(findings):
    if not findings:
        console.print("[green]No findings.[/green]")
        return
    table = Table(title="Security Findings")
    table.add_column("Severity")
    table.add_column("Check")
    table.add_column("SPARTA")
    table.add_column("Description")
    for f in findings[:10]:
        table.add_row(f.get("severity"), f.get("check_type"), f.get("sparta_id", "N/A"), f.get("description")[:60])
    console.print(table)


@app.command()
def version():
    console.print(f"[bold]SatScan v{config.version}[/]")


if __name__ == "__main__":
    app()
