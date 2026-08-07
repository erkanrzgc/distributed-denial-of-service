from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Static


class DetectionMenuScreen(Screen):
    CSS = """
    DetectionMenuScreen {
        align: center middle;
    }
    #detect-container {
        width: 50;
        height: auto;
        border: solid $border;
        background: $surface;
        padding: 1 2;
    }
    .detect-btn {
        width: 100%;
        margin: 1 0;
    }
    """

    BINDINGS = [
        ("escape", "back", "Back"),
        ("1", "monitor", "Monitor"),
        ("2", "anomaly", "Anomaly"),
        ("3", "entropy", "Entropy"),
        ("4", "fingerprint", "Fingerprint"),
        ("5", "alert", "Alert"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="detect-container"):
            yield Static("[bold blue]DETECTION MODULES[/]")
            yield Static()
            yield Button(" 1 — Live Traffic Monitor", id="btn_monitor", variant="primary", classes="detect-btn")
            yield Button(" 2 — Anomaly Scanner", id="btn_anomaly", variant="primary", classes="detect-btn")
            yield Button(" 3 — Entropy Analyzer", id="btn_entropy", variant="primary", classes="detect-btn")
            yield Button(" 4 — Fingerprint Tracker", id="btn_fingerprint", variant="primary", classes="detect-btn")
            yield Button(" 5 — Alert System", id="btn_alert", variant="primary", classes="detect-btn")
            yield Static()
            yield Button(" Back (Esc) ", id="btn_back", variant="default")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        if btn == "btn_back":
            self.app.pop_screen()
        elif btn == "btn_monitor":
            self.app.action_show_detection_live({"detect_type": "monitor"})
        elif btn == "btn_anomaly":
            self.app.action_show_detection_live({"detect_type": "anomaly"})
        elif btn == "btn_entropy":
            self.app.action_show_detection_live({"detect_type": "entropy"})
        elif btn == "btn_fingerprint":
            self.app.action_show_detection_live({"detect_type": "fingerprint"})
        elif btn == "btn_alert":
            self.app.action_show_detection_live({"detect_type": "alert"})

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_monitor(self) -> None:
        self.app.action_show_detection_live({"detect_type": "monitor"})

    def action_anomaly(self) -> None:
        self.app.action_show_detection_live({"detect_type": "anomaly"})

    def action_entropy(self) -> None:
        self.app.action_show_detection_live({"detect_type": "entropy"})

    def action_fingerprint(self) -> None:
        self.app.action_show_detection_live({"detect_type": "fingerprint"})

    def action_alert(self) -> None:
        self.app.action_show_detection_live({"detect_type": "alert"})
