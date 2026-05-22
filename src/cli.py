@app.command()
def scan(
    file_path: Path = typer.Argument(..., help="File to scan"),
    ai: bool = typer.Option(False, "--ai", help="Enable AI explanations"),
    agent: Optional[str] = typer.Option(None, "--agent", help="Run agentic investigation"),
    ml: bool = typer.Option(False, "--ml", help="Enable ML anomaly detection"),
    output: str = typer.Option("html", help="Report format: json, html, pdf"),
    model: str = typer.Option("llama3.2", help="Ollama model"),
):
    """Full security scan with AI/ML and reporting."""
    try:
        parser = CCSDSParser()
        packets = parser.parse_file(file_path)

        engine = SecurityCheckEngine(enable_ml=ml)
        findings = engine.run_all(packets)

        ai_explanations = {}
        if ai or agent:
            from src.ai.explainers import enrich_findings_with_ai
            from src.ai.agent import SatScanAgent
            findings = enrich_findings_with_ai(findings, model=model)

            if agent:
                agent_obj = SatScanAgent(model=model)
                agent_result = agent_obj.investigate(agent, findings, len(packets))
                console.print("\n[bold cyan]Agent Analysis:[/]\n", agent_result)

        reporter = ReportGenerator()
        report_path = reporter.generate(
            findings=findings,
            packets=packets,
            output_format=output,
            ai_explanations=ai_explanations,
            scan_file=str(file_path)
        )

        console.print(f"[bold green]Scan completed successfully![/] Report → {report_path}")
        _print_findings_summary(findings)

    except Exception as e:
        console.print(f"[bold red]Scan error:[/] {e}")
        raise typer.Exit(1)
