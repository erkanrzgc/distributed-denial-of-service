from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Static


class DefenseMenuScreen(Screen):
    CSS = """
    DefenseMenuScreen { align: center middle; }
    #menu-container {
        width: 44; height: auto; border: solid green;
        background: $surface; padding: 1 2;
    }
    .defense-btn { width: 100%; margin: 1 0; }
    #btn-row { height: 3; align-horizontal: center; margin-top: 1; }
    .act-btn { width: 12; margin: 0 1; }
    Button:focus { text-style: bold reverse; }
    """

    BINDINGS = [
        ("escape", "back", "Back"),
        ("1", "proxy", "Proxy"),
        ("2", "rate", "Rate"),
        ("3", "firewall", "FW"),
        ("4", "challenge", "Challenge"),
        ("5", "shaper", "Shaper"),
        ("6", "waf", "WAF"),
        ("7", "dataguard", "Guard"),
        ("up", "focus_prev", "Up"),
        ("down", "focus_next", "Down"),
        ("enter", "activate", "Select"),
    ]

    DEFENSE_MAP = {
        "btn_proxy": "reverse_proxy", "btn_rate": "rate_limiter", "btn_firewall": "dynamic_firewall",
        "btn_challenge": "challenge", "btn_shaper": "traffic_shaper", "btn_waf": "waf",
        "btn_dataguard": "data_guard",
    }

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="menu-container"):
            yield Static("  defense")
            yield Static()
            yield Button("Reverse Proxy", id="btn_proxy", variant="success", classes="defense-btn")
            yield Button("Rate Limiter", id="btn_rate", variant="success", classes="defense-btn")
            yield Button("Firewall", id="btn_firewall", variant="success", classes="defense-btn")
            yield Button("Challenge", id="btn_challenge", variant="success", classes="defense-btn")
            yield Button("Traffic Shaper", id="btn_shaper", variant="success", classes="defense-btn")
            yield Button("WAF Scanner", id="btn_waf", variant="success", classes="defense-btn")
            yield Button("Data Guard", id="btn_dataguard", variant="success", classes="defense-btn")
            yield Static()
            with Horizontal(id="btn-row"):
                yield Button("Back", id="btn_back", variant="default", classes="act-btn")
        yield Footer()

    def on_mount(self) -> None:
        try: self.query_one("#btn_proxy", Button).focus()
        except: pass

    def _get_buttons(self) -> list[Button]:
        return [w for w in self.query(".defense-btn") if isinstance(w, Button)]

    def action_focus_next(self) -> None:
        btns = self._get_buttons()
        if not btns: return
        for i, b in enumerate(btns):
            if b.has_focus: btns[(i+1)%len(btns)].focus(); return
        btns[0].focus()

    def action_focus_prev(self) -> None:
        btns = self._get_buttons()
        if not btns: return
        for i, b in enumerate(btns):
            if b.has_focus: btns[(i-1)%len(btns)].focus(); return
        btns[-1].focus()

    def action_activate(self) -> None:
        if self.focused and isinstance(self.focused, Button): self.focused.press()

    def _start(self, m: str) -> None: self.app.action_show_defense_live({"defense_type": m})
    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn = event.button.id
        if btn == "btn_back": self.app.pop_screen()
        elif btn in self.DEFENSE_MAP: self._start(self.DEFENSE_MAP[btn])

    def action_back(self) -> None: self.app.pop_screen()
    def action_proxy(self) -> None: self._start("reverse_proxy")
    def action_rate(self) -> None: self._start("rate_limiter")
    def action_firewall(self) -> None: self._start("dynamic_firewall")
    def action_challenge(self) -> None: self._start("challenge")
    def action_shaper(self) -> None: self._start("traffic_shaper")
    def action_waf(self) -> None: self._start("waf")
    def action_dataguard(self) -> None: self._start("data_guard")
