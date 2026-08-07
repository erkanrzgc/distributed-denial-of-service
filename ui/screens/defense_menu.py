from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Select, Static


class DefenseMenuScreen(Screen):
    CSS = """
    DefenseMenuScreen {
        align: center middle;
    }
    #defense-container {
        width: 50;
        height: auto;
        border: solid $border;
        background: $surface;
        padding: 1 2;
    }
    .defense-btn {
        width: 100%;
        margin: 1 0;
    }
    """

    BINDINGS = [
        ("escape", "back", "Back"),
        ("1", "proxy", "Proxy"),
        ("2", "rate", "Rate Limit"),
        ("3", "firewall", "Firewall"),
        ("4", "challenge", "Challenge"),
        ("5", "shaper", "Shaper"),
        ("6", "waf", "WAF"),
        ("7", "dataguard", "Data Guard"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="defense-container"):
            yield Static("[bold green]DEFENSE MODULES[/]")
            yield Static()
            yield Button(" 1 — Reverse Proxy (WAF + Rate Limit)", id="btn_proxy", variant="success", classes="defense-btn")
            yield Button(" 2 — Rate Limiter", id="btn_rate", variant="success", classes="defense-btn")
            yield Button(" 3 — Dynamic Firewall", id="btn_firewall", variant="success", classes="defense-btn")
            yield Button(" 4 — Challenge-Response", id="btn_challenge", variant="success", classes="defense-btn")
            yield Button(" 5 — Traffic Shaper", id="btn_shaper", variant="success", classes="defense-btn")
            yield Button(" 6 — WAF Scanner", id="btn_waf", variant="success", classes="defense-btn")
            yield Button(" 7 — Data Leak Guard", id="btn_dataguard", variant="success", classes="defense-btn")
            yield Static()
            yield Button("Back", id="btn_back", variant="default")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        if btn == "btn_back":
            self.app.pop_screen()
        elif btn == "btn_proxy":
            self.app.action_show_defense_live({"defense_type": "reverse_proxy"})
        elif btn == "btn_rate":
            self.app.action_show_defense_live({"defense_type": "rate_limiter"})
        elif btn == "btn_firewall":
            self.app.action_show_defense_live({"defense_type": "dynamic_firewall"})
        elif btn == "btn_challenge":
            self.app.action_show_defense_live({"defense_type": "challenge"})
        elif btn == "btn_shaper":
            self.app.action_show_defense_live({"defense_type": "traffic_shaper"})
        elif btn == "btn_waf":
            self.app.action_show_defense_live({"defense_type": "waf"})
        elif btn == "btn_dataguard":
            self.app.action_show_defense_live({"defense_type": "data_guard"})

    def action_back(self) -> None:
        self.app.pop_screen()

    def action_proxy(self) -> None:
        self.app.action_show_defense_live({"defense_type": "reverse_proxy"})

    def action_rate(self) -> None:
        self.app.action_show_defense_live({"defense_type": "rate_limiter"})

    def action_firewall(self) -> None:
        self.app.action_show_defense_live({"defense_type": "dynamic_firewall"})

    def action_challenge(self) -> None:
        self.app.action_show_defense_live({"defense_type": "challenge"})

    def action_shaper(self) -> None:
        self.app.action_show_defense_live({"defense_type": "traffic_shaper"})

    def action_waf(self) -> None:
        self.app.action_show_defense_live({"defense_type": "waf"})

    def action_dataguard(self) -> None:
        self.app.action_show_defense_live({"defense_type": "data_guard"})
