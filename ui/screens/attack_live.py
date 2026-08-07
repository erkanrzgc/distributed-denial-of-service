import asyncio
import time

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Static

from core.engine import session_manager, registry
from core.session import SessionStatus


class AttackLiveScreen(Screen):
    CSS = """
    AttackLiveScreen {
        align: center middle;
    }
    #live-container {
        width: 100%;
        height: 100%;
        border: solid red;
        background: $surface;
        padding: 1 2;
    }
    #status-bar {
        height: 3;
        dock: top;
        background: #1a0000;
        padding: 0 1;
    }
    .stat-box {
        width: 1fr;
        border: solid $border;
        padding: 1;
        margin: 1;
        text-align: center;
    }
    .stat-value {
        text-style: bold;
        color: $text;
    }
    .stat-label {
        text-style: dim;
        color: $text-muted;
    }
    #log-box {
        height: 10;
        border: solid $border;
        margin: 1;
        padding: 0 1;
        overflow-y: auto;
    }
    """

    BINDINGS = [
        ("s", "stop", "Stop"),
        ("p", "pause", "Pause"),
        ("escape", "back", "Back"),
    ]

    stats_packets = reactive("0")
    stats_rate = reactive("0/s")
    stats_success = reactive("0%")
    stats_bandwidth = reactive("0 Mbps")
    stats_errors = reactive("0")
    stats_duration = reactive("0s")

    def __init__(self, config: dict, **kwargs):
        super().__init__(**kwargs)
        self.config = config
        self._update_timer = None
        self._log_lines = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Container(id="live-container"):
            with Horizontal(id="status-bar"):
                yield Label(f"ATTACK: {self.config.get('attack_type', '?')} → {self.config.get('target', '?')}", id="status-title")
                yield Static(id="status-indicator")

            with Horizontal():
                with Container(classes="stat-box"):
                    yield Label("Packets", classes="stat-label")
                    yield Static(self.stats_packets, id="val-packets", classes="stat-value")
                with Container(classes="stat-box"):
                    yield Label("Rate", classes="stat-label")
                    yield Static(self.stats_rate, id="val-rate", classes="stat-value")
                with Container(classes="stat-box"):
                    yield Label("Success", classes="stat-label")
                    yield Static(self.stats_success, id="val-success", classes="stat-value")
                with Container(classes="stat-box"):
                    yield Label("Bandwidth", classes="stat-label")
                    yield Static(self.stats_bandwidth, id="val-bw", classes="stat-value")
                with Container(classes="stat-box"):
                    yield Label("Errors", classes="stat-label")
                    yield Static(self.stats_errors, id="val-errors", classes="stat-value")
                with Container(classes="stat-box"):
                    yield Label("Duration", classes="stat-label")
                    yield Static(self.stats_duration, id="val-duration", classes="stat-value")

            yield Static("Activity Log:", id="log-header")
            yield Static("Starting attack...", id="log-box")

            with Horizontal():
                yield Button("STOP", id="btn_stop", variant="error")
                yield Button("PAUSE", id="btn_pause", variant="warning")
                yield Button("Back", id="btn_back", variant="default")

        yield Footer()

    def on_mount(self) -> None:
        self._update_timer = self.set_interval(0.25, self._update_stats)
        self._start_attack()

    def on_unmount(self) -> None:
        if self._update_timer:
            self._update_timer.stop()

    def _start_attack(self) -> None:
        module_cls = registry.get_module(self.config["attack_type"], "attack")
        if not module_cls:
            self.query_one("#log-box", Static).update(f"Unknown attack: {self.config['attack_type']}")
            return

        target = self.config.get("target", "localhost")
        session = session_manager.create_session(
            module=self.config["attack_type"],
            target=target,
            mode="attack",
        )
        self._session = session
        module = module_cls(session=session, event_bus=None)

        async def run_attack():
            kwargs = {
                "target": self.config.get("target", "localhost"),
                "port": self.config.get("port", 443),
                "rate": self.config.get("rate", 1000),
                "concurrent": self.config.get("concurrent", 100),
                **({"method": self.config.get("method", "GET")} if self.config["attack_type"] in ("http_flood", "layer7") else {}),
            }
            await module.start(**kwargs)

        self._task = asyncio.create_task(run_attack())

    def _add_log(self, msg: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        self._log_lines.append(f"[dim]{timestamp}[/] {msg}")
        if len(self._log_lines) > 50:
            self._log_lines = self._log_lines[-50:]
        try:
            self.query_one("#log-box", Static).update("\n".join(self._log_lines[-8:]))
        except Exception:
            pass

    def _update_stats(self) -> None:
        session = getattr(self, "_session", None)
        if not session:
            return

        stats = session.stats
        self.stats_packets = f"{stats.packets_sent:,}"
        elapsed = time.monotonic() - stats.start_time if stats.start_time else 1
        rate = int(stats.packets_sent / elapsed) if elapsed > 0 else 0
        self.stats_rate = f"{rate:,}/s"
        self.stats_success = f"{stats.success_rate:.1f}%"
        self.stats_bandwidth = f"{stats.bandwidth_mbps:.2f} Mbps"
        self.stats_errors = str(stats.errors)
        self.stats_duration = f"{session.duration:.1f}s"

        try:
            self.query_one("#val-packets", Static).update(self.stats_packets)
            self.query_one("#val-rate", Static).update(self.stats_rate)
            self.query_one("#val-success", Static).update(self.stats_success)
            self.query_one("#val-bw", Static).update(self.stats_bandwidth)
            self.query_one("#val-errors", Static).update(self.stats_errors)
            self.query_one("#val-duration", Static).update(self.stats_duration)
        except Exception:
            pass

        if session.status == SessionStatus.COMPLETED:
            self._add_log("[green]Attack completed[/]")
        elif session.status == SessionStatus.FAILED:
            self._add_log(f"[red]Attack failed: {session.error_message}[/]")

        if stats.packets_sent % 100 == 0 and stats.packets_sent > 0:
            self._add_log(f"Packets: {stats.packets_sent:,} | Rate: {rate:,}/s | Err: {stats.errors}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_stop":
            self._stop_attack()
        elif event.button.id == "btn_pause":
            self._toggle_pause(event)
        elif event.button.id == "btn_back":
            self._stop_attack()
            self.app.pop_screen()

    def action_stop(self) -> None:
        self._stop_attack()
        self.app.pop_screen()

    def action_pause(self) -> None:
        self._toggle_pause(None)

    def _stop_attack(self) -> None:
        if hasattr(self, "_session"):
            self._session.stop()
        if hasattr(self, "_task") and self._task and not self._task.done():
            self._task.cancel()

    def _toggle_pause(self, event) -> None:
        session = getattr(self, "_session", None)
        if not session:
            return
        if session.status == SessionStatus.RUNNING:
            session.pause()
            btn = self.query_one("#btn_pause", Button)
            btn.label = "RESUME"
        elif session.status == SessionStatus.PAUSED:
            session.resume()
            btn = self.query_one("#btn_pause", Button)
            btn.label = "PAUSE"
