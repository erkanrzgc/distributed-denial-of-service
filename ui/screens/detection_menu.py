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
        width: 52;
        height: auto;
        border: solid $border;
        background: $surface;
        padding: 1 2;
    }
    .detect-btn {
        width: 100%;
        margin: 1 0;
    }
    Button:focus {
        text-style: bold reverse;
    }
    """

    BINDINGS = [
        ("escape", "back", "Back"),
        ("1", "monitor", "Monitor"),
        ("2", "anomaly", "Anomaly"),
        ("3", "entropy", "Entropy"),
        ("4", "fingerprint", "Finger"),
        ("5", "alert", "Alert"),
        ("up", "focus_prev", "Up"),
        ("down", "focus_next", "Down"),
        ("enter", "activate", "Select"),
    ]

    DETECT_MAP = {
        "btn_monitor": "monitor", "btn_anomaly": "anomaly", "btn_entropy": "entropy",
        "btn_fingerprint": "fingerprint", "btn_alert": "alert",
    }

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
            yield Button(" Back (Esc) ", id="btn_back", variant="default", classes="detect-btn")
        yield Footer()

    def on_mount(self) -> None:
        try:
            self.query_one("#btn_monitor", Button).focus()
        except Exception:
            pass

    def _get_buttons(self) -> list[Button]:
        return [w for w in self.query(".detect-btn") if isinstance(w, Button)]

    def action_focus_next(self) -> None:
        btns = self._get_buttons()
        if not btns:
            return
        for i, b in enumerate(btns):
            if b.has_focus:
                btns[(i + 1) % len(btns)].focus()
                return
        btns[0].focus()

    def action_focus_prev(self) -> None:
        btns = self._get_buttons()
        if not btns:
            return
        for i, b in enumerate(btns):
            if b.has_focus:
                btns[(i - 1) % len(btns)].focus()
                return
        btns[-1].focus()

    def action_activate(self) -> None:
        focused = self.focused
        if focused and isinstance(focused, Button):
            focused.press()

    def _start(self, m: str) -> None:
        self.app.action_show_detection_live({"detect_type": m})

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        if btn == "btn_back":
            self.app.pop_screen()
        elif btn in self.DETECT_MAP:
            self._start(self.DETECT_MAP[btn])

    def action_back(self) -> None: self.app.pop_screen()
    def action_monitor(self) -> None: self._start("monitor")
    def action_anomaly(self) -> None: self._start("anomaly")
    def action_entropy(self) -> None: self._start("entropy")
    def action_fingerprint(self) -> None: self._start("fingerprint")
    def action_alert(self) -> None: self._start("alert")
