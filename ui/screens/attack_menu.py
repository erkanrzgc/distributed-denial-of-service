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
        width: 45;
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
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="menu-container"):
            yield Static("[bold red]ATTACK MODULES[/]")
            yield Static()
            yield Button("HTTP Flood — HTTP/HTTPS request flood", id="btn_http", variant="error", classes="attack-btn")
            yield Button("SYN Flood — TCP SYN packet flood", id="btn_syn", variant="error", classes="attack-btn")
            yield Button("UDP Flood — UDP packet flood", id="btn_udp", variant="error", classes="attack-btn")
            yield Button("Slowloris — Connection exhaustion", id="btn_slowloris", variant="error", classes="attack-btn")
            yield Button("Slow Read — Response draining", id="btn_slowread", variant="error", classes="attack-btn")
            yield Button("Layer 7 — App-layer simulation", id="btn_layer7", variant="error", classes="attack-btn")
            yield Button("ICMP Flood — Ping flood", id="btn_icmp", variant="error", classes="attack-btn")
            yield Button("Amplification — DNS/NTP amp", id="btn_amp", variant="error", classes="attack-btn")
            yield Static()
            yield Button("Back", id="btn_back", variant="default")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        module_map = {
            "btn_http": "http_flood",
            "btn_syn": "syn_flood",
            "btn_udp": "udp_flood",
            "btn_slowloris": "slowloris",
            "btn_slowread": "slow_read",
            "btn_layer7": "layer7",
            "btn_icmp": "icmp_flood",
            "btn_amp": "amplification",
        }
        if btn == "btn_back":
            self.app.pop_screen()
        elif btn in module_map:
            self.app.call_later(self.app.action_show_attack_wizard, module_map[btn])

    def action_back(self) -> None:
        self.app.pop_screen()
