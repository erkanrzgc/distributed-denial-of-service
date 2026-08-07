from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Select, Static


class AttackMenuScreen(Screen):
    CSS = """
    AttackMenuScreen {
        align: center middle;
    }
    #menu-container {
        width: 48;
        height: auto;
        border: solid red;
        background: $surface;
        padding: 1 2;
    }
    .attack-btn {
        width: 100%;
        margin: 1 0;
    }
    """

    BINDINGS = [
        ("escape", "back", "Back"),
        ("1", "http", "HTTP Flood"),
        ("2", "syn", "SYN Flood"),
        ("3", "udp", "UDP Flood"),
        ("4", "slowloris", "Slowloris"),
        ("5", "slowread", "Slow Read"),
        ("6", "layer7", "Layer 7"),
        ("7", "icmp", "ICMP Flood"),
        ("8", "amp", "Amplification"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="menu-container"):
            yield Static("[bold red]ATTACK MODULES[/]")
            yield Static()
            yield Button(" 1 — HTTP Flood — HTTP/HTTPS request flood", id="btn_http", variant="error", classes="attack-btn")
            yield Button(" 2 — SYN Flood — TCP SYN packet flood", id="btn_syn", variant="error", classes="attack-btn")
            yield Button(" 3 — UDP Flood — UDP packet flood", id="btn_udp", variant="error", classes="attack-btn")
            yield Button(" 4 — Slowloris — Connection exhaustion", id="btn_slowloris", variant="error", classes="attack-btn")
            yield Button(" 5 — Slow Read — Response draining", id="btn_slowread", variant="error", classes="attack-btn")
            yield Button(" 6 — Layer 7 — App-layer simulation", id="btn_layer7", variant="error", classes="attack-btn")
            yield Button(" 7 — ICMP Flood — Ping flood", id="btn_icmp", variant="error", classes="attack-btn")
            yield Button(" 8 — Amplification — DNS/NTP amp", id="btn_amp", variant="error", classes="attack-btn")
            yield Static()
            yield Button(" Back (Esc) ", id="btn_back", variant="default")
        yield Footer()

    MODULE_MAP = {
        "btn_http": "http_flood",
        "btn_syn": "syn_flood",
        "btn_udp": "udp_flood",
        "btn_slowloris": "slowloris",
        "btn_slowread": "slow_read",
        "btn_layer7": "layer7",
        "btn_icmp": "icmp_flood",
        "btn_amp": "amplification",
    }

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        if btn == "btn_back":
            self.app.pop_screen()
        elif btn in self.MODULE_MAP:
            self.app.call_later(self.app.action_show_attack_wizard, self.MODULE_MAP[btn])

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_http(self) -> None:
        self.app.call_later(self.app.action_show_attack_wizard, "http_flood")

    def action_syn(self) -> None:
        self.app.call_later(self.app.action_show_attack_wizard, "syn_flood")

    def action_udp(self) -> None:
        self.app.call_later(self.app.action_show_attack_wizard, "udp_flood")

    def action_slowloris(self) -> None:
        self.app.call_later(self.app.action_show_attack_wizard, "slowloris")

    def action_slowread(self) -> None:
        self.app.call_later(self.app.action_show_attack_wizard, "slow_read")

    def action_layer7(self) -> None:
        self.app.call_later(self.app.action_show_attack_wizard, "layer7")

    def action_icmp(self) -> None:
        self.app.call_later(self.app.action_show_attack_wizard, "icmp_flood")

    def action_amp(self) -> None:
        self.app.call_later(self.app.action_show_attack_wizard, "amplification")
