import asyncio

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, Select, Static, Switch

from utils.target_profiler import scan_target


class AttackWizardScreen(Screen):
    CSS = """
    AttackWizardScreen {
        align: center middle;
    }
    #wizard-container {
        width: 76;
        height: auto;
        border: solid $border;
        background: $surface;
        padding: 1 2;
    }
    .form-row {
        height: 3;
        margin: 1 0;
    }
    .form-label {
        width: 18;
        text-align: right;
        padding: 0 1;
    }
    .form-input {
        width: 42;
    }
    #scan-result {
        height: auto;
        border: solid $border;
        margin: 1 0;
        padding: 1;
        background: $surface;
    }
    .suggest-btn {
        width: 100%;
        margin: 0;
    }
    """

    def __init__(self, attack_module: str = "http_flood", **kwargs):
        super().__init__(**kwargs)
        self.attack_module = attack_module
        self._profile = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        attack_options = [
            ("HTTP Flood", "http_flood"),
            ("SYN Flood", "syn_flood"),
            ("UDP Flood", "udp_flood"),
            ("Slowloris", "slowloris"),
            ("Slow Read", "slow_read"),
            ("Layer 7", "layer7"),
            ("ICMP Flood", "icmp_flood"),
            ("Amplification", "amplification"),
        ]

        with Container(id="wizard-container"):
            yield Static("[bold red]ATTACK CONFIGURATION[/]", id="wizard-title")

            with Horizontal(classes="form-row"):
                yield Label("Attack Type:", classes="form-label")
                yield Select(attack_options, value=self.attack_module, id="attack_type", classes="form-input")

            with Horizontal(classes="form-row"):
                yield Label("Target:", classes="form-label")
                yield Input(placeholder="https://example.com or 1.2.3.4:443", id="target", classes="form-input")

            with Horizontal(classes="form-row"):
                yield Label("Port:", classes="form-label")
                yield Input(placeholder="443", value="443", id="port", classes="form-input")

            with Horizontal(classes="form-row"):
                yield Label("Rate (req/s):", classes="form-label")
                yield Input(placeholder="1000", value="1000", id="rate", classes="form-input")

            with Horizontal(classes="form-row"):
                yield Label("Concurrency:", classes="form-label")
                yield Input(placeholder="100", value="100", id="concurrent", classes="form-input")

            with Horizontal(classes="form-row"):
                yield Label("Duration (s):", classes="form-label")
                yield Input(placeholder="0 = unlimited", value="0", id="duration", classes="form-input")

            with Horizontal(classes="form-row"):
                yield Label("HTTP Method:", classes="form-label")
                yield Select([("GET", "GET"), ("POST", "POST"), ("HEAD", "HEAD")], value="GET", id="method", classes="form-input")

            with Horizontal(classes="form-row"):
                yield Label("Spoof IP:", classes="form-label")
                yield Switch(value=False, id="spoof", classes="form-input")

            yield Button("Scan Target", id="btn_scan", variant="primary")

            yield Static(id="scan-result")

            Static()
            with Horizontal():
                yield Button("START ATTACK", id="btn_start", variant="error")
                yield Button("Back", id="btn_back", variant="default")

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_back":
            self.app.pop_screen()
        elif event.button.id == "btn_start":
            self._start_attack()
        elif event.button.id == "btn_scan":
            self._run_scan()

    def _start_attack(self) -> None:
        config = {
            "attack_type": self.query_one("#attack_type", Select).value,
            "target": self.query_one("#target", Input).value,
            "port": int(self.query_one("#port", Input).value or "443"),
            "rate": int(self.query_one("#rate", Input).value or "1000"),
            "concurrent": int(self.query_one("#concurrent", Input).value or "100"),
            "duration": int(self.query_one("#duration", Input).value or "0"),
            "method": self.query_one("#method", Select).value,
            "spoof": self.query_one("#spoof", Switch).value,
        }
        self.app.action_show_attack_live(config)

    def _run_scan(self) -> None:
        target = self.query_one("#target", Input).value
        if not target:
            self.query_one("#scan-result", Static).update("[yellow]Enter a target first[/]")
            return

        self.query_one("#scan-result", Static).update("[dim]Scanning...[/]")
        asyncio.create_task(self._do_scan(target))

    async def _do_scan(self, target: str) -> None:
        try:
            profile = await scan_target(target, scan_ports=True)
            self._profile = profile
            self._show_profile(profile)

            if profile.port:
                self.query_one("#port", Input).value = str(profile.port)
            if profile.is_https:
                self.query_one("#port", Input).value = str(profile.port or 443)
        except Exception as e:
            self.query_one("#scan-result", Static).update(f"[red]Scan failed: {e}[/]")

    def _show_profile(self, p) -> None:
        lines = ["[bold]Target Profile[/]"]
        lines.append(f"  IP: {p.ip or '?'}  |  Status: {p.status_code or '?'}  |  Time: {p.response_time*1000:.0f}ms")

        if p.server:
            lines.append(f"  Server: {p.server}")
        if p.tech_stack:
            lines.append(f"  Tech: {', '.join(p.tech_stack)}")
        if p.waf:
            lines.append(f"  [yellow]WAF: {', '.join(p.waf)}[/]")
        else:
            lines.append("  WAF: None")
        if p.tls_version:
            lines.append(f"  TLS: {p.tls_version}")
        if p.open_ports:
            lines.append(f"  Open ports: {', '.join(str(x) for x in p.open_ports)}")
        if p.rate_limited:
            lines.append("  [red]Rate-limited![/]")

        if p.suggested_attacks:
            lines.append("")
            lines.append("[bold green]Suggested Attacks:[/]")
            for s in p.suggested_attacks[:4]:
                icon = "[green]" if s["priority"] == "high" else "[yellow]" if s["priority"] == "medium" else "[dim]"
                lines.append(f"  {icon}{s['attack']}[/] — {s['reason']}")

        if p.errors:
            lines.append(f"\n[dim]{'; '.join(p.errors[:3])}[/]")

        self.query_one("#scan-result", Static).update("\n".join(lines))
