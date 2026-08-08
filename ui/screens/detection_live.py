import asyncio

from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.reactive import reactive
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Static

from core.engine import session_manager, registry
from utils.log_writer import create_log, append_log, write_session_summary


class DetectionLiveScreen(Screen):
    CSS = """
    DetectionLiveScreen {
        align: center middle;
    }
    #live-container {
        width: 100%;
        height: 100%;
        border: solid blue;
        background: $surface;
        padding: 1 2;
    }
    #status-bar {
        height: 3;
        dock: top;
        background: #00001a;
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

    stats_packets = reactive("0")
    stats_rate = reactive("0/s")
    stats_anomalies = reactive("0")
    stats_connections = reactive("0")
    stats_unique = reactive("0")
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
                yield Label(f"DETECTION: {self.config.get('detect_type', '?')}", id="status-title")
                yield Static(" SCANNING", id="status-indicator")

            with Horizontal():
                with Container(classes="stat-box"):
                    yield Label("Packets", classes="stat-label")
                    yield Static(self.stats_packets, id="val-pkt", classes="stat-value")
                with Container(classes="stat-box"):
                    yield Label("Rate (pps)", classes="stat-label")
                    yield Static(self.stats_rate, id="val-rate", classes="stat-value")
                with Container(classes="stat-box"):
                    yield Label("Anomalies", classes="stat-label")
                    yield Static(self.stats_anomalies, id="val-anomaly", classes="stat-value")
                with Container(classes="stat-box"):
                    yield Label("Connections", classes="stat-label")
                    yield Static(self.stats_connections, id="val-conn", classes="stat-value")
                with Container(classes="stat-box"):
                    yield Label("Unique IPs", classes="stat-label")
                    yield Static(self.stats_unique, id="val-unique", classes="stat-value")
                with Container(classes="stat-box"):
                    yield Label("Duration", classes="stat-label")
                    yield Static(self.stats_duration, id="val-duration", classes="stat-value")

            yield Static("Top Talkers:", id="tops-header")
            yield Static("Waiting for data...", id="tops-list")

            with Horizontal():
                yield Button("STOP", id="btn_stop", variant="error")
                yield Button("Back", id="btn_back", variant="default")

        yield Footer()

    def on_mount(self) -> None:
        self._stat_timer = self.set_interval(0.5, self._update_stats)
        self._start_detection()
        self._log_file = create_log("monitor", "detection",
                                     self.config.get("detect_type", "detection"))

    def on_unmount(self) -> None:
        if self._stat_timer:
            self._stat_timer.stop()
        if self._log_file and hasattr(self, "_session"):
            write_session_summary(self._log_file, self._session.to_dict())

    def _start_detection(self) -> None:
        module_cls = registry.get_module(self.config["detect_type"], "detection")
        if not module_cls:
            return
        session = session_manager.create_session(
            module=self.config["detect_type"],
            target="eth0",
            mode="detection",
        )
        self._session = session
        module = module_cls(session=session, event_bus=None)

        async def run_detection():
            await module.start()

        self._task = asyncio.create_task(run_detection())

    def _update_stats(self) -> None:
        session = getattr(self, "_session", None)
        if not session:
            return
        stats = session.stats

        self.stats_packets = f"{stats.packets_sent:,}"
        self.stats_rate = f"{stats.packets_sent:,}"
        self.stats_anomalies = f"{getattr(stats, 'rate_hits', 0):,}"
        self.stats_connections = f"{getattr(stats, 'errors', 0):,}"
        self.stats_unique = f"0"
        self.stats_duration = f"{session.duration:.1f}s"

        try:
            self.query_one("#val-pkt", Static).update(self.stats_packets)
            self.query_one("#val-rate", Static).update(self.stats_rate)
            self.query_one("#val-anomaly", Static).update(self.stats_anomalies)
            self.query_one("#val-conn", Static).update(self.stats_connections)
            self.query_one("#val-unique", Static).update(self.stats_unique)
            self.query_one("#val-duration", Static).update(self.stats_duration)
        except Exception:
            pass

        if self._log_file and stats.packets_sent % 100 == 0:
            append_log(self._log_file,
                        f"pkts={stats.packets_sent} anomalies={getattr(stats, 'rate_hits', 0)}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_stop":
            self._stop_detection()
        elif event.button.id == "btn_back":
            self._stop_detection()
            self.app.pop_screen()

    def _stop_detection(self) -> None:
        if hasattr(self, "_session"):
            self._session.stop()
        if hasattr(self, "_task") and self._task and not self._task.done():
            self._task.cancel()
