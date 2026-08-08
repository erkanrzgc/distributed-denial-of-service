import asyncio
import time

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Static

from core.engine import session_manager, registry
from utils.log_writer import create_log, append_log, write_session_summary
from core.session import SessionStatus


class DefenseLiveScreen(Screen):
    CSS = """
    DefenseLiveScreen {
        align: center middle;
    }
    #live-container {
        width: 100%;
        height: 100%;
        border: solid green;
        background: $surface;
        padding: 1 2;
    }
    #status-bar {
        height: 3;
        dock: top;
        background: #001a00;
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
    """

    stats_req = reactive("0")
    stats_blocked = reactive("0")
    stats_passed = reactive("0")
    stats_waf = reactive("0")
    stats_rate = reactive("0")
    stats_duration = reactive("0s")

    def __init__(self, config: dict, **kwargs):
        super().__init__(**kwargs)
        self.config = config
        self._stat_timer = None
        self._log_file = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="live-container"):
            with Horizontal(id="status-bar"):
                yield Label(f"DEFENSE: {self.config.get('defense_type', '?')}", id="status-title")
                yield Static(" ACTIVE", id="status-indicator")

            with Horizontal():
                with Container(classes="stat-box"):
                    yield Label("Requests", classes="stat-label")
                    yield Static(self.stats_req, id="val-req", classes="stat-value")
                with Container(classes="stat-box"):
                    yield Label("Blocked", classes="stat-label")
                    yield Static(self.stats_blocked, id="val-blocked", classes="stat-value")
                with Container(classes="stat-box"):
                    yield Label("Passed", classes="stat-label")
                    yield Static(self.stats_passed, id="val-passed", classes="stat-value")
                with Container(classes="stat-box"):
                    yield Label("WAF Hits", classes="stat-label")
                    yield Static(self.stats_waf, id="val-waf", classes="stat-value")
                with Container(classes="stat-box"):
                    yield Label("Rate", classes="stat-label")
                    yield Static(self.stats_rate, id="val-rate", classes="stat-value")
                with Container(classes="stat-box"):
                    yield Label("Uptime", classes="stat-label")
                    yield Static(self.stats_duration, id="val-duration", classes="stat-value")

            yield Static("Blocked IPs:", id="blocked-header")
            yield Static("No blocked IPs yet", id="blocked-list")

            with Horizontal():
                yield Button("STOP", id="btn_stop", variant="error")
                yield Button("Back", id="btn_back", variant="default")

        yield Footer()

    def on_mount(self) -> None:
        self._stat_timer = self.set_interval(0.5, self._update_stats)
        self._start_defense()
        self._log_file = create_log(
            self.config.get("defense_type", "defense") + "://localhost",
            "defense",
            self.config.get("defense_type", "defense")
        )

    def on_unmount(self) -> None:
        if self._stat_timer:
            self._stat_timer.stop()
        if self._log_file and hasattr(self, "_session"):
            write_session_summary(self._log_file, self._session.to_dict())

    def _start_defense(self) -> None:
        module_cls = registry.get_module(self.config["defense_type"], "defense")
        if not module_cls:
            return

        session = session_manager.create_session(
            module=self.config["defense_type"],
            target="localhost:8080",
            mode="defense",
        )
        self._session = session
        module = module_cls(session=session, event_bus=None)

        async def run_defense():
            kwargs = {
                "listen": "0.0.0.0:8080",
                "backend": "http://localhost:3000",
                "rate_limit": 100,
            }
            await module.start(**kwargs)

        self._task = asyncio.create_task(run_defense())

    def _update_stats(self) -> None:
        session = getattr(self, "_session", None)
        if not session:
            return
        stats = session.stats

        self.stats_req = f"{stats.packets_sent:,}"
        self.stats_blocked = f"{getattr(stats, 'blocked_count', 0):,}"
        self.stats_passed = f"{getattr(stats, 'passed_count', 0):,}"
        self.stats_waf = f"{getattr(stats, 'waf_triggers', 0):,}"
        self.stats_rate = f"{getattr(stats, 'rate_hits', 0):,}/s"
        self.stats_duration = f"{session.duration:.1f}s"
        self._log_stats = (stats.packets_sent, getattr(stats, 'blocked_count', 0))

        try:
            self.query_one("#val-req", Static).update(self.stats_req)
            self.query_one("#val-blocked", Static).update(self.stats_blocked)
            self.query_one("#val-passed", Static).update(self.stats_passed)
            self.query_one("#val-waf", Static).update(self.stats_waf)
            self.query_one("#val-rate", Static).update(self.stats_rate)
            self.query_one("#val-duration", Static).update(self.stats_duration)
        except Exception:
            pass

        if self._log_file and stats.packets_sent % 50 == 0:
            append_log(self._log_file, f"req={stats.packets_sent} blocked={getattr(stats, 'blocked_count', 0)} waf={getattr(stats, 'waf_triggers', 0)}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_stop":
            self._stop_defense()
        elif event.button.id == "btn_back":
            self._stop_defense()
            self.app.pop_screen()

    def _stop_defense(self) -> None:
        if hasattr(self, "_session"):
            self._session.stop()
        if hasattr(self, "_task") and self._task and not self._task.done():
            self._task.cancel()
