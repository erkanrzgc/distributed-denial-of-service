from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Label, Static

from utils.reporter import REPORT_DIR


class ReportsScreen(Screen):
    CSS = """
    ReportsScreen {
        align: center middle;
    }
    #reports-container {
        width: 60;
        height: auto;
        border: solid $border;
        background: $surface;
        padding: 1 2;
    }
    """

    BINDINGS = [("escape", "back", "Back")]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="reports-container"):
            yield Static("[bold]REPORTS[/]")
            yield Static()
            if REPORT_DIR.exists() and list(REPORT_DIR.glob("*")):
                for f in sorted(REPORT_DIR.glob("*"), reverse=True)[:20]:
                    yield Label(f"[dim]{f.name}[/]")
            else:
                yield Static("[dim]No reports yet. Run an attack or defense to generate reports.[/]")
            yield Static()
            yield Button("Export Current Session", id="btn_export", variant="primary")
            yield Button("Back", id="btn_back", variant="default")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn_back":
            self.app.pop_screen()
        elif event.button.id == "btn_export":
            self.app.push_screen("reports")

    def action_back(self) -> None:
        self.app.pop_screen()
