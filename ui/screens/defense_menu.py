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

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="defense-container"):
            yield Static("[bold green]DEFENSE MODULES[/]")
            yield Static()
            yield Button("Reverse Proxy (WAF + Rate Limit)", id="btn_proxy", variant="success", classes="defense-btn")
            yield Button("Rate Limiter", id="btn_rate", variant="success", classes="defense-btn")
            yield Button("Dynamic Firewall", id="btn_firewall", variant="success", classes="defense-btn")
            yield Button("Challenge-Response", id="btn_challenge", variant="success", classes="defense-btn")
            yield Button("Traffic Shaper", id="btn_shaper", variant="success", classes="defense-btn")
            yield Button("WAF Scanner", id="btn_waf", variant="success", classes="defense-btn")
            yield Button("Data Leak Guard", id="btn_dataguard", variant="success", classes="defense-btn")
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
