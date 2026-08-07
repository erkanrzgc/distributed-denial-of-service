import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import structlog
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.syntax import Syntax
from rich.tree import Tree

logger = structlog.get_logger(__name__)

REPORT_DIR = Path.home() / ".config" / "ddos-toolkit" / "reports"


class Reporter:
    def __init__(self) -> None:
        self.console = Console()
        REPORT_DIR.mkdir(parents=True, exist_ok=True)

    def print_result(self, session_data: dict[str, Any], title: str = "Report") -> None:
        table = Table(title=f"[bold]{title}[/bold] - {session_data.get('session_id', 'N/A')}")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("Module", session_data.get("module", "N/A"))
        table.add_row("Target", session_data.get("target", "N/A"))
        table.add_row("Status", session_data.get("status", "N/A"))
        table.add_row("Duration", f"{session_data.get('duration', 0):.2f}s")
        table.add_row("Packets Sent", str(session_data.get("packets_sent", 0)))
        table.add_row("Errors", str(session_data.get("errors", 0)))
        table.add_row("Success Rate", f"{session_data.get('success_rate', 0):.1f}%")
        table.add_row("Bandwidth", f"{session_data.get('bandwidth_mbps', 0):.2f} Mbps")
        self.console.print(table)

    def print_defense_status(self, stats: dict[str, Any]) -> None:
        layout = Layout()
        layout.split_row(
            Layout(Panel(str(stats.get("packets_sent", 0)), title="Requests")),
            Layout(Panel(str(stats.get("blocked_count", 0)), title="Blocked")),
            Layout(Panel(str(stats.get("passed_count", 0)), title="Passed")),
            Layout(Panel(f"{stats.get('bandwidth_mbps', 0):.1f} Mbps", title="Bandwidth")),
        )
        self.console.print(layout)

    def export_json(self, data: dict[str, Any], filename: Optional[str] = None) -> str:
        filename = filename or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = REPORT_DIR / filename
        data["exported_at"] = datetime.now().isoformat()
        filepath.write_text(json.dumps(data, indent=2, default=str))
        logger.info("report_exported", path=str(filepath))
        return str(filepath)

    def export_html(self, data: dict[str, Any], filename: Optional[str] = None) -> str:
        filename = filename or f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = REPORT_DIR / filename

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DDoS Toolkit Report</title>
  <style>
    body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
    h1 {{ color: #58a6ff; }}
    .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1.5rem; margin: 1rem 0; }}
    .stat {{ display: inline-block; margin: 0.5rem 1rem; }}
    .stat-val {{ font-size: 2rem; font-weight: bold; color: #58a6ff; }}
    .stat-label {{ font-size: 0.85rem; color: #8b949e; text-transform: uppercase; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
    th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #30363d; }}
    th {{ color: #8b949e; font-weight: 600; }}
    .error {{ color: #f85149; }}
    .success {{ color: #3fb950; }}
  </style>
</head>
<body>
  <h1>DDoS Toolkit Report</h1>
  <div class="card">
    <div class="stat"><div class="stat-val">{data.get('packets_sent', 0)}</div><div class="stat-label">Packets Sent</div></div>
    <div class="stat"><div class="stat-val">{data.get('errors', 0)}</div><div class="stat-label">Errors</div></div>
    <div class="stat"><div class="stat-val">{data.get('success_rate', 0):.1f}%</div><div class="stat-label">Success Rate</div></div>
    <div class="stat"><div class="stat-val">{data.get('bandwidth_mbps', 0):.2f}</div><div class="stat-label">Mbps</div></div>
    <div class="stat"><div class="stat-val">{data.get('duration', 0):.1f}s</div><div class="stat-label">Duration</div></div>
  </div>
  <div class="card">
    <table>
      <tr><th>Property</th><th>Value</th></tr>
      <tr><td>Session ID</td><td>{data.get('session_id', 'N/A')}</td></tr>
      <tr><td>Module</td><td>{data.get('module', 'N/A')}</td></tr>
      <tr><td>Target</td><td>{data.get('target', 'N/A')}</td></tr>
      <tr><td>Status</td><td class="{'success' if data.get('status') == 'completed' else 'error'}">{data.get('status', 'N/A')}</td></tr>
    </table>
  </div>
</body>
</html>"""
        filepath.write_text(html)
        logger.info("report_exported_html", path=str(filepath))
        return str(filepath)

    def print_json(self, data: dict[str, Any]) -> None:
        formatted = json.dumps(data, indent=2, default=str)
        syntax = Syntax(formatted, "json", theme="monokai", line_numbers=True)
        self.console.print(Panel(syntax, title="JSON Output"))


reporter = Reporter()
