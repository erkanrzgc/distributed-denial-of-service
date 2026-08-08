import asyncio
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, Select, Static, Switch

from utils.target_profiler import scan_target
from utils.validators import validate_target

LOG_DIR = Path("logs")


class AttackWizardScreen(Screen):
    CSS = """
    AttackWizardScreen {
        align: center middle;
    }
    #wizard-container {
        width: 78;
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
        width: 15;
        text-align: right;
        padding: 0 1;
    }
    .form-input {
        width: 45;
    }
    #scan-panel {
        height: auto;
        border: solid green;
        margin: 1 0;
        padding: 1;
        background: $surface;
    }
    Button:focus, Input:focus, Select:focus {
        text-style: bold reverse;
    }
    """

    BINDINGS = [
        ("escape", "back", "Back"),
        ("ctrl+s", "start", "Start"),
        ("ctrl+n", "scan", "Scan"),
        ("up", "focus_prev", "Up"),
        ("down", "focus_next", "Down"),
        ("tab", "focus_next", "Next"),
    ]

    def __init__(self, attack_module: str = "http_flood", **kwargs):
        super().__init__(**kwargs)
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
            yield Static("[bold red]ATTACK WIZARD[/]", id="wizard-title")

            yield Static()
            yield Static("  1. Enter target & scan")
            with Horizontal(classes="form-row"):
                yield Label("Target:", classes="form-label")
                yield Input(placeholder="example.com or https://...", id="target", classes="form-input")

            with Horizontal(classes="form-row"):
                yield Label("", classes="form-label")
                yield Button(" Scan Target (Ctrl+N) ", id="btn_scan", variant="primary")

            yield Static(id="scan-panel")

            yield Static("  2. Configure & launch")
            with Horizontal(classes="form-row"):
                yield Label("Attack Type:", classes="form-label")
                yield Select(attack_options, value="http_flood", id="attack_type", classes="form-input")

            with Horizontal(classes="form-row"):
                yield Label("Port:", classes="form-label")
                yield Input(placeholder="443", value="443", id="port", classes="form-input")

            with Horizontal(classes="form-row"):
                yield Label("Rate:", classes="form-label")
                yield Input(placeholder="1000", value="1000", id="rate", classes="form-input")

            with Horizontal(classes="form-row"):
                yield Label("Concurrency:", classes="form-label")
                yield Input(placeholder="100", value="100", id="concurrent", classes="form-input")

            with Horizontal(classes="form-row"):
                yield Label("Duration:", classes="form-label")
                yield Input(placeholder="0 = unlimited", value="0", id="duration", classes="form-input")

            with Horizontal(classes="form-row"):
                yield Label("Method:", classes="form-label")
                yield Select([("GET", "GET"), ("POST", "POST"), ("HEAD", "HEAD")], value="GET", id="method", classes="form-input")

            with Horizontal(classes="form-row"):
                yield Label("Spoof IP:", classes="form-label")
                yield Switch(value=False, id="spoof", classes="form-input")

            Static()
            with Horizontal():
                yield Button(" Launch Attack ", id="btn_start", variant="error")
                yield Button(" Go Back ", id="btn_back", variant="default")

        yield Footer()

    def on_mount(self) -> None:
        try:
            self.query_one("#target", Input).focus()
        except Exception:
            pass

    def _get_focusables(self) -> list:
        return [
            w for w in self.query(".form-input, #btn_scan, #btn_start, #btn_back")
            if hasattr(w, "focus")
        ]

    def action_focus_next(self) -> None:
        widgets = self._get_focusables()
        if not widgets:
            return
        for i, w in enumerate(widgets):
            if w.has_focus:
                widgets[(i + 1) % len(widgets)].focus()
                return
        widgets[0].focus()

    def action_focus_prev(self) -> None:
        widgets = self._get_focusables()
        if not widgets:
            return
        for i, w in enumerate(widgets):
            if w.has_focus:
                widgets[(i - 1) % len(widgets)].focus()
                return
        widgets[-1].focus()

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_start(self) -> None:
        self._start_attack()

    def action_scan(self) -> None:
        self._run_scan()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn_back":
            self.app.pop_screen()
        elif btn_id == "btn_start":
            self._start_attack()
        elif btn_id == "btn_scan":
            self._run_scan()

    def _run_scan(self) -> None:
        target = self.query_one("#target", Input).value.strip()
        if not target:
            self.query_one("#scan-panel", Static).update("[red]Enter a target first[/]")
            return

        valid, host, error = validate_target(target)
        if not valid:
            self.query_one("#scan-panel", Static).update(f"[red]Invalid target: {error}[/]")
            return

        self.query_one("#scan-panel", Static).update(f"[dim]Scanning {host}...[/]")
        asyncio.create_task(self._do_scan(target))

    async def _do_scan(self, target: str) -> None:
        try:
            profile = await scan_target(target, scan_ports=True)
            self._profile = profile
            self._show_profile(profile)

            if profile.port:
                self.query_one("#port", Input).value = str(profile.port)
            if profile.suggested_attacks:
                sug = profile.suggested_attacks[0]
                self.query_one("#attack_type", Select).value = sug["attack"]
                for k, v in sug.get("config", {}).items():
                    if k == "port":
                        self.query_one("#port", Input).value = str(v)
                    elif k == "rate":
                        self.query_one("#rate", Input).value = str(v)
                    elif k == "concurrent":
                        self.query_one("#concurrent", Input).value = str(v)
                    elif k == "method":
                        self.query_one("#method", Select).value = v
        except Exception as e:
            self.query_one("#scan-panel", Static).update(f"[red]Scan error: {e}[/]")

    def _show_profile(self, p) -> None:
        lines = []
        lines.append(f"[green]{p.ip}[/]  HTTP {p.status_code}  {p.response_time*1000:.0f}ms")

        if p.server:
            lines.append(f"[dim]{p.server}[/]  TLS {p.tls_version or '?'}")
        if p.waf:
            lines.append(f"[yellow]WAF: {', '.join(p.waf)}[/]")
        if p.open_ports:
            lines.append(f"[dim]ports: {', '.join(str(x) for x in p.open_ports)}[/]")
        if p.rate_limited:
            lines.append("[red]rate-limited[/]")

        if p.suggested_attacks:
            lines.append("")
            lines.append("[bold]try these:[/]")
            for s in p.suggested_attacks[:3]:
                icon = ">" if s["priority"] == "high" else "-"
                lines.append(f"  {icon} {s['attack']} — {s['reason']}")

        self.query_one("#scan-panel", Static).update("\n".join(lines))

    def _start_attack(self) -> None:
        raw_target = self.query_one("#target", Input).value.strip()
        valid, host, error = validate_target(raw_target)
        if not valid:
            self.query_one("#scan-panel", Static).update(f"[red]Cannot start: {error}[/]")
            return

        config = {
            "attack_type": self.query_one("#attack_type", Select).value,
            "target": raw_target,
            "port": int(self.query_one("#port", Input).value or "443"),
            "rate": int(self.query_one("#rate", Input).value or "1000"),
            "concurrent": int(self.query_one("#concurrent", Input).value or "100"),
            "duration": int(self.query_one("#duration", Input).value or "0"),
            "method": self.query_one("#method", Select).value,
            "spoof": self.query_one("#spoof", Switch).value,
        }
        self._ensure_log_dir(host)
        self.app.action_show_attack_live(config)

    @staticmethod
    def _ensure_log_dir(host: str) -> None:
        clean = host.replace("/", "_").replace("\\", "_").replace(":", "_")[:64]
        (LOG_DIR / clean).mkdir(parents=True, exist_ok=True)
