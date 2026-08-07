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
    """

    BINDINGS = [
        ("a", "go_attack", "Attack"),
        ("d", "go_defense", "Defense"),
        ("t", "go_detection", "Detection"),
        ("r", "go_reports", "Reports"),
        ("s", "go_settings", "Settings"),
        ("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Container(
            Static("[bold white on #1f6feb] DDOS TOOLKIT v1.0 [/]", id="title"),
            Static("[dim]Attack | Defense | Detect — All in one terminal[/]", id="subtitle"),
            Button(" Attack (A)", id="btn_attack", variant="error", classes="menu-btn"),
            Button(" Defense (D)", id="btn_defense", variant="success", classes="menu-btn"),
            Button(" Detection (T)", id="btn_detection", variant="primary", classes="menu-btn"),
            Static(),
            Button(" Reports (R)", id="btn_reports", classes="menu-btn"),
            Button(" Settings (S)", id="btn_settings", classes="menu-btn"),
            Static(),
            Button(" Quit (Q)", id="btn_quit", variant="default", classes="menu-btn"),
            id="main-container",
        )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn_attack":
            self.app.action_show_attack_menu()
        elif btn_id == "btn_defense":
            self.app.action_show_defense_menu()
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

    def action_go_detection(self) -> None:
        self.app.action_show_detection_menu()

    def action_go_reports(self) -> None:
        self.app.action_show_reports()

    def action_go_settings(self) -> None:
        self.app.action_show_settings()
