import asyncio
import time

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
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
        height: 1;
        dock: top;
        background: #1a0000;
        padding: 0 1;
    }
    #main-area {
        height: 1fr;
    }
    #stats-panel {
        width: 50;
        border: solid $border;
        padding: 1;
        margin: 1 0;
    }
    #log-panel {
        width: 1fr;
        border: solid $border;
        padding: 1;
        margin: 1 0;
        overflow-y: auto;
    }
    #controls {
        dock: bottom;
        height: 3;
        padding: 0 1;
    }
    .stat-row {
        height: 1;
        margin: 0;
    }
    .stat-label {
        width: 16;
    }
    .stat-bar {
        width: 30;
    }
    .low { color: #3fb950; }
    .mid { color: #d29922; }
    .high { color: #f85149; }
    """

    BINDINGS = [
        ("s", "stop", "Stop"),
        ("p", "pause", "Pause"),
        ("escape", "back", "Back"),
    ]

    def __init__(self, config: dict, **kwargs):
        super().__init__(**kwargs)
        self.config = config
        self._stat_timer = None
        self._log_lines = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Container(id="live-container"):
            with Horizontal(id="status-bar"):
                yield Label(f"ATTACK: {self.config.get('attack_type', '?')} → {self.config.get('target', '?')}", id="status-title")

            with Horizontal(id="main-area"):
                with Vertical(id="stats-panel"):
                    yield Static("[bold]STATS[/]")
                    yield Static("[dim]Packets Sent:[/]  0", id="st-packets")
                    yield Static("[dim]Rate:[/]  0/s", id="st-rate")
                    yield Static("[dim]Success:[/]  0%", id="st-success")
                    yield Static("[dim]Bandwidth:[/]  0.00 Mbps", id="st-bw")
                    yield Static("[dim]Errors:[/]  0", id="st-errors")
                    yield Static("[dim]Duration:[/]  0s", id="st-duration")

                with Vertical(id="log-panel"):
                    yield Static("[bold]LOG[/]")
                    yield Static("Starting attack...", id="st-log")

            with Horizontal(id="controls"):
                yield Button("STOP", id="btn_stop", variant="error")
                yield Button("PAUSE", id="btn_pause", variant="warning")
                yield Button("Back", id="btn_back", variant="default")

        yield Footer()

    def on_mount(self) -> None:
        self._stat_timer = self.set_interval(0.25, self._update_stats)
        self._start_attack()

    def on_unmount(self) -> None:
        if self._stat_timer:
            self._stat_timer.stop()

    def _start_attack(self) -> None:
        module_cls = registry.get_module(self.config["attack_type"], "attack")
        if not module_cls:
            self.query_one("#st-log", Static).update(f"Unknown attack: {self.config['attack_type']}")
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

    def _add_log(self, msg: str, style: str = "") -> None:
        timestamp = time.strftime("%H:%M:%S")
        if style:
            self._log_lines.append(f"[dim]{timestamp}[/] [{style}]{msg}[/]")
        else:
            self._log_lines.append(f"[dim]{timestamp}[/] {msg}")
        if len(self._log_lines) > 100:
            self._log_lines = self._log_lines[-100:]
        try:
            self.query_one("#st-log", Static).update("\n".join(self._log_lines[-12:]))
        except Exception:
            pass

    def _update_stats(self) -> None:
        session = getattr(self, "_session", None)
        if not session:
            return

        stats = session.stats
        elapsed = time.monotonic() - stats.start_time if stats.start_time else 1
        rate = int(stats.packets_sent / elapsed) if elapsed > 0 else 0
        success = stats.success_rate

        s_class = "low" if success >= 90 else ("mid" if success >= 50 else "high")
        r_class = ""
        e_class = "" if stats.errors < 50 else "high"

        try:
            self.query_one("#st-packets", Static).update(f"[dim]Packets Sent:[/]  {stats.packets_sent:,}")
            self.query_one("#st-rate", Static).update(f"[dim]Rate:[/]  {rate:,}/s")
            self.query_one("#st-success", Static).update(f"[dim]Success:[/]  [{s_class}]{success:.1f}%[/]")
            self.query_one("#st-bw", Static).update(f"[dim]Bandwidth:[/]  {stats.bandwidth_mbps:.2f} Mbps")
            self.query_one("#st-errors", Static).update(f"[dim]Errors:[/]  [{e_class}]{stats.errors}[/]")
            self.query_one("#st-duration", Static).update(f"[dim]Duration:[/]  {session.duration:.1f}s")
        except Exception:
            pass

        if session.status == SessionStatus.COMPLETED:
            self._add_log("Attack completed", style="green")
        elif session.status == SessionStatus.FAILED:
            self._add_log(f"Attack failed: {session.error_message}", style="red")

        if stats.packets_sent % 100 == 0 and stats.packets_sent > 0:
            self._add_log(f"Sent: {stats.packets_sent:,} | Rate: {rate:,}/s | Err: {stats.errors} | {success:.0f}%")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_stop":
            self._stop_attack()
        elif event.button.id == "btn_pause":
            self._toggle_pause()
        elif event.button.id == "btn_back":
            self._stop_attack()
            self.app.pop_screen()

    def action_stop(self) -> None:
        self._stop_attack()
        self.app.pop_screen()

    def action_pause(self) -> None:
        self._toggle_pause()

    def _stop_attack(self) -> None:
        if hasattr(self, "_session"):
            self._session.stop()
        if hasattr(self, "_task") and self._task and not self._task.done():
            self._task.cancel()

    def _toggle_pause(self) -> None:
        session = getattr(self, "_session", None)
        if not session:
            return
        btn = self.query_one("#btn_pause", Button)
        if session.status == SessionStatus.RUNNING:
            session.pause()
            btn.label = "RESUME"
            self._add_log("PAUSED", style="yellow")
        elif session.status == SessionStatus.PAUSED:
            session.resume()
            btn.label = "PAUSE"
            self._add_log("RESUMED", style="green")
