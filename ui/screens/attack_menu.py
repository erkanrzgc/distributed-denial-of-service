from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Static


class AttackMenuScreen(Screen):
    CSS = """
    AttackMenuScreen { align: center middle; }
    #menu-container {
        width: 52; height: auto; border: solid red;
        background: $surface; padding: 1 2;
    }
    .attack-btn { width: 100%; margin: 1 0; }
    #btn-row { height: 3; align-horizontal: center; margin-top: 1; }
    .act-btn { width: 12; margin: 0 1; }
    Button:focus { text-style: bold reverse; }
    """

    BINDINGS = [
        ("escape", "back", "Back"),
        ("1", "http", "HTTP"),
        ("2", "syn", "SYN"),
        ("3", "udp", "UDP"),
        ("4", "slowloris", "Slowloris"),
        ("5", "slowread", "Slow Read"),
        ("6", "layer7", "Layer 7"),
        ("7", "icmp", "ICMP"),
        ("8", "amp", "AMP"),
        ("up", "focus_prev", "Up"),
        ("down", "focus_next", "Down"),
        ("enter", "activate", "Select"),
    ]

    MODULE_MAP = {
        "btn_http": "http_flood", "btn_syn": "syn_flood", "btn_udp": "udp_flood",
        "btn_slowloris": "slowloris", "btn_slowread": "slow_read", "btn_layer7": "layer7",
        "btn_icmp": "icmp_flood", "btn_amp": "amplification",
    }

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="menu-container"):
            yield Static("  attack type")
            yield Static()
            yield Button("HTTP Flood", id="btn_http", variant="error", classes="attack-btn")
            yield Button("SYN Flood", id="btn_syn", variant="error", classes="attack-btn")
            yield Button("UDP Flood", id="btn_udp", variant="error", classes="attack-btn")
            yield Button("Slowloris", id="btn_slowloris", variant="error", classes="attack-btn")
            yield Button("Slow Read", id="btn_slowread", variant="error", classes="attack-btn")
            yield Button("Layer 7", id="btn_layer7", variant="error", classes="attack-btn")
            yield Button("ICMP Flood", id="btn_icmp", variant="error", classes="attack-btn")
            yield Button("Amplification", id="btn_amp", variant="error", classes="attack-btn")
            yield Static()
            with Horizontal(id="btn-row"):
                yield Button("Back", id="btn_back", variant="default", classes="act-btn")
        yield Footer()

    def on_mount(self) -> None:
        try:
            self.query_one("#btn_http", Button).focus()
        except Exception:
            pass

    def _get_buttons(self) -> list[Button]:
        return [w for w in self.query(".attack-btn") if isinstance(w, Button)]

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

    def _start_module(self, module: str) -> None:
        self.app.call_later(self.app.action_show_attack_wizard, module)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        if btn == "btn_back":
            self.app.pop_screen()
        elif btn in self.MODULE_MAP:
            self._start_module(self.MODULE_MAP[btn])

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_http(self) -> None: self._start_module("http_flood")
    def action_syn(self) -> None: self._start_module("syn_flood")
    def action_udp(self) -> None: self._start_module("udp_flood")
    def action_slowloris(self) -> None: self._start_module("slowloris")
    def action_slowread(self) -> None: self._start_module("slow_read")
    def action_layer7(self) -> None: self._start_module("layer7")
    def action_icmp(self) -> None: self._start_module("icmp_flood")
    def action_amp(self) -> None: self._start_module("amplification")
