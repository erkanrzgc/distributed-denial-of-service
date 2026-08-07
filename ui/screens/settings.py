from textual.app import ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, Select, Static, Switch

from core.config import get_config
from ui.themes import AppTheme


class SettingsScreen(Screen):
    CSS = """
    SettingsScreen {
        align: center middle;
    }
    #settings-container {
        width: 60;
        height: auto;
        border: solid $border;
        background: $surface;
        padding: 1 2;
    }
    .setting-row {
        height: 3;
        margin: 1 0;
    }
    .setting-label {
        width: 25;
        text-align: right;
        padding: 0 1;
    }
    .setting-input {
        width: 30;
    }
    """

    BINDINGS = [("escape", "back", "Back")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        config = get_config()

        with Container(id="settings-container"):
            yield Static("[bold]SETTINGS[/]")
            yield Static()

            with Horizontal(classes="setting-row"):
                yield Label("Theme:", classes="setting-label")
                yield Select(
                    [(t.value.title(), t.value) for t in AppTheme],
                    value=config.ui.theme,
                    id="theme",
                    classes="setting-input",
                )

            with Horizontal(classes="setting-row"):
                yield Label("Refresh Rate (ms):", classes="setting-label")
                yield Input(value=str(config.ui.refresh_rate), id="refresh_rate", classes="setting-input")

            with Horizontal(classes="setting-row"):
                yield Label("Mouse Support:", classes="setting-label")
                yield Switch(value=config.ui.mouse_support, id="mouse", classes="setting-input")

            with Horizontal(classes="setting-row"):
                yield Label("Default Rate:", classes="setting-label")
                yield Input(value=str(config.attack.default_rate), id="default_rate", classes="setting-input")

            with Horizontal(classes="setting-row"):
                yield Label("Spoof IP Default:", classes="setting-label")
                yield Switch(value=config.attack.spoof_enabled, id="spoof_default", classes="setting-input")

            with Horizontal(classes="setting-row"):
                yield Label("Rate Limit (req/s):", classes="setting-label")
                yield Input(value=str(config.defense.rate_limit), id="rate_limit", classes="setting-input")

            with Horizontal(classes="setting-row"):
                yield Label("Alert Webhook URL:", classes="setting-label")
                yield Input(value=config.alert.webhook_url or "", id="webhook_url", classes="setting-input")

            with Horizontal(classes="setting-row"):
                yield Label("Alert Threshold (rps):", classes="setting-label")
                yield Input(value=str(config.alert.threshold_rps), id="alert_threshold", classes="setting-input")

            yield Static()
            with Horizontal():
                yield Button("SAVE", id="btn_save", variant="primary")
                yield Button("Back", id="btn_back", variant="default")

        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_back":
            self.app.pop_screen()
        elif event.button.id == "btn_save":
            self._save_settings()

    def _save_settings(self) -> None:
        config = get_config()
        try:
            config.ui.theme = self.query_one("#theme", Select).value
            config.ui.refresh_rate = int(self.query_one("#refresh_rate", Input).value)
            config.ui.mouse_support = self.query_one("#mouse", Switch).value
            config.attack.default_rate = int(self.query_one("#default_rate", Input).value)
            config.attack.spoof_enabled = self.query_one("#spoof_default", Switch).value
            config.defense.rate_limit = int(self.query_one("#rate_limit", Input).value)
            webhook = self.query_one("#webhook_url", Input).value
            config.alert.webhook_url = webhook if webhook else None
            config.alert.threshold_rps = int(self.query_one("#alert_threshold", Input).value)
            config.save()
            self.notify("Settings saved!")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def action_back(self) -> None:
        self.app.pop_screen()
