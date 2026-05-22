import json
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

from rich.console import Console
from jinja2 import Template

console = Console()

class ReportGenerator:
    def __init__(self):
        self.output_dir = Path("reports")
        self.output_dir.mkdir(exist_ok=True)

    def generate(self, findings: List[Dict], packets: List, output_format: str = "html",
                 ai_explanations: Dict = None, scan_file: str = "input") -> Path:
        """Generate report in requested format."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"satscan_report_{Path(scan_file).stem}_{timestamp}"

        report_data = {
            "timestamp": datetime.now().isoformat(),
            "input_file": str(scan_file),
            "total_packets": len(packets),
            "findings_count": len(findings),
            "findings": findings,
            "ai_enabled": ai_explanations is not None
        }

        if output_format == "json":
            path = self.output_dir / f"{base_name}.json"
            path.write_text(json.dumps(report_data, indent=2, default=str))
            return path

        elif output_format == "html":
            return self._generate_html(report_data, base_name, ai_explanations)

        elif output_format == "pdf":
            return self._generate_pdf(report_data, base_name, ai_explanations)

        return Path("report_generated")

    def _generate_html(self, data: Dict, base_name: str, ai_explanations: Dict = None) -> Path:
        template_str = """
        <!DOCTYPE html>
        <html><head><title>SatScan Report</title>
        <style>body{font-family:Arial;} table{border-collapse:collapse;} th,td{border:1px solid #ccc;padding:8px;}</style>
        </head><body>
        <h1>SatScan Security Report</h1>
        <p><strong>File:</strong> {{ data.input_file }} | Packets: {{ data.total_packets }} | Findings: {{ data.findings_count }}</p>
        <h2>Findings</h2>
        <table>
        <tr><th>Severity</th><th>Check</th><th>SPARTA</th><th>Description</th><th>AI Explanation</th></tr>
        {% for f in data.findings %}
        <tr>
            <td>{{ f.severity }}</td>
            <td>{{ f.check_type }}</td>
            <td>{{ f.get('sparta_id', 'N/A') }}</td>
            <td>{{ f.description }}</td>
            <td>{{ f.get('ai_explanation', 'N/A') }}</td>
        </tr>
        {% endfor %}
        </table>
        </body></html>
        """
        template = Template(template_str)
        html = template.render(data=data, findings=data['findings'])

        path = self.output_dir / f"{base_name}.html"
        path.write_text(html)
        console.print(f"[green]HTML report generated:[/] {path}")
        return path

    def _generate_pdf(self, data: Dict, base_name: str, ai_explanations=None):
        try:
            from weasyprint import HTML
            html_path = self._generate_html(data, base_name + "_temp", ai_explanations)
            pdf_path = html_path.with_suffix(".pdf")
            HTML(string=html_path.read_text()).write_pdf(pdf_path)
            html_path.unlink()  # Clean temp
            return pdf_path
        except ImportError:
            console.print("[yellow]WeasyPrint not installed. Falling back to HTML.[/]")
            return self._generate_html(data, base_name, ai_explanations)
