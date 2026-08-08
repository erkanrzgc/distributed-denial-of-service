from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Static


class MainMenuScreen(Screen):
    CSS = """
    MainMenuScreen {
        align: center middle;
    }
    #main-container {
        width: 60;
        height: auto;
        border: solid $border;
        background: $surface;
        padding: 1 2;
    }
    #title {
        text-align: center;
        width: 100%;
        padding: 1 0;
    }
    #subtitle {
        text-align: center;
        width: 100%;
        padding: 0 0 1 0;
    }
    .menu-btn {
        width: 100%;
        margin: 1 0;
    }
    Button:focus {
        text-style: bold reverse;
    }
    """

    BINDINGS = [
        ("a", "go_attack", "Attack"),
        ("d", "go_defense", "Defense"),
        ("e", "go_stress", "Stress"),
        ("t", "go_detection", "Detection"),
        ("r", "go_reports", "Reports"),
        ("s", "go_settings", "Settings"),
        ("q", "quit", "Quit"),
        ("up", "focus_prev", "Up"),
        ("down", "focus_next", "Down"),
        ("enter", "activate", "Select"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Container(
            Static("[bold white on #1f6feb] DDOS TOOLKIT v1.0 [/]", id="title"),
            Static("[dim]Attack · Defense · Stress · Detect | Red & Blue Team[/]", id="subtitle"),
            Button(" Attack (A)", id="btn_attack", variant="error", classes="menu-btn"),
            Button(" Defense (D)", id="btn_defense", variant="success", classes="menu-btn"),
            Button(" Stress Test (E)", id="btn_stress", variant="warning", classes="menu-btn"),
            Button(" Detection (T)", id="btn_detection", variant="primary", classes="menu-btn"),
            Static(),
            Button(" Reports (R)", id="btn_reports", classes="menu-btn"),
            Button(" Settings (S)", id="btn_settings", classes="menu-btn"),
            Static(),
            Button(" Quit (Q)", id="btn_quit", variant="default", classes="menu-btn"),
            id="main-container",
        )
        yield Footer()

    def on_mount(self) -> None:
        try:
            self.query_one("#btn_attack", Button).focus()
        except Exception:
            pass

    def _get_buttons(self) -> list[Button]:
        return [
            w for w in self.query(".menu-btn")
            if isinstance(w, Button)
        ]

    def action_focus_next(self) -> None:
        btns = self._get_buttons()
        if not btns:
            return
        for i, b in enumerate(btns):
            if b.has_focus:
                next_btn = btns[(i + 1) % len(btns)]
                next_btn.focus()
                return
        btns[0].focus()

    def action_focus_prev(self) -> None:
        btns = self._get_buttons()
        if not btns:
            return
        for i, b in enumerate(btns):
            if b.has_focus:
                prev_btn = btns[(i - 1) % len(btns)]
                prev_btn.focus()
                return
        btns[-1].focus()

    def action_activate(self) -> None:
        focused = self.focused
        if focused and isinstance(focused, Button):
            focused.press()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn_attack":
            self.app.action_show_attack_menu()
        elif btn_id == "btn_defense":
            self.app.action_show_defense_menu()
        elif btn_id == "btn_stress":
            self.app.action_show_attack_wizard("http_flood")
        elif btn_id == "btn_detection":
            self.app.action_show_detection_menu()
        elif btn_id == "btn_reports":
            self.app.action_show_reports()
        elif btn_id == "btn_settings":
            self.app.action_show_settings()
        elif btn_id == "btn_quit":
            self.app.exit()

    def action_go_attack(self) -> None:
        self.app.action_show_attack_menu()

    def action_go_defense(self) -> None:
        self.app.action_show_defense_menu()

    def action_go_stress(self) -> None:
        self.app.action_show_attack_wizard("http_flood")

    def action_go_detection(self) -> None:
        self.app.action_show_detection_menu()

    def action_go_reports(self) -> None:
        self.app.action_show_reports()

    def action_go_settings(self) -> None:
        self.app.action_show_settings()
