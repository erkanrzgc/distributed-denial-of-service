from textual.app import App
from textual.screen import Screen

from ui.screens.main_menu import MainMenuScreen
from ui.screens.attack_menu import AttackMenuScreen
from ui.screens.attack_wizard import AttackWizardScreen
from ui.screens.attack_live import AttackLiveScreen
from ui.screens.defense_menu import DefenseMenuScreen
from ui.screens.defense_live import DefenseLiveScreen
from ui.screens.detection_menu import DetectionMenuScreen
from ui.screens.detection_live import DetectionLiveScreen
from ui.screens.report_viewer import ReportsScreen
from ui.screens.settings import SettingsScreen

from core.config import get_config


class DDoSToolkitApp(App):
    TITLE = "DDoS Toolkit"
    SUB_TITLE = "Attack \u2022 Defense \u2022 Stress \u2022 Detect"
    CSS = """
    Screen {
        background: $surface;
    }
    """

    def on_mount(self) -> None:
        config = get_config()
        self.title = "DDoS Toolkit"
        self.sub_title = "Attack \u2022 Defense \u2022 Detection"
        self.push_screen(MainMenuScreen())

    def action_show_attack_menu(self) -> None:
        self.push_screen(AttackMenuScreen())

    def action_show_defense_menu(self) -> None:
        self.push_screen(DefenseMenuScreen())

    def action_show_detection_menu(self) -> None:
        self.push_screen(DetectionMenuScreen())

    def action_show_reports(self) -> None:
        self.push_screen(ReportsScreen())

    def action_show_settings(self) -> None:
        self.push_screen(SettingsScreen())

    def action_show_attack_wizard(self, module: str) -> None:
        self.push_screen(AttackWizardScreen(attack_module=module))

    def action_show_attack_live(self, config: dict) -> None:
        self.push_screen(AttackLiveScreen(config))

    def action_show_defense_live(self, config: dict) -> None:
        self.push_screen(DefenseLiveScreen(config))

    def action_show_detection_live(self, config: dict) -> None:
        self.push_screen(DetectionLiveScreen(config))


def run_tui() -> None:
    try:
        app = DDoSToolkitApp()
        app.run()
    except KeyboardInterrupt:
        pass
