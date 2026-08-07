from enum import Enum
from typing import Optional

from rich.style import Style
from rich.theme import Theme


class AppTheme(str, Enum):
    DARK = "dark"
    LIGHT = "light"
    NEON = "neon"
    MATRIX = "matrix"


THEMES = {
    AppTheme.DARK: Theme({
        "primary": "bold cyan",
        "secondary": "dim white",
        "accent": "bold yellow",
        "danger": "bold red",
        "success": "bold green",
        "warning": "yellow",
        "info": "blue",
        "background": "on #0d1117",
        "surface": "on #161b22",
        "border": "#30363d",
        "text": "#c9d1d9",
        "text-muted": "#8b949e",
        "attack": "bold red",
        "defense": "bold green",
        "detection": "bold blue",
        "header": "bold white on #1f6feb",
        "progress": "#58a6ff",
        "gauge": "#3fb950",
        "sparkline": "#d2a8ff",
    }),
    AppTheme.LIGHT: Theme({
        "primary": "bold blue",
        "secondary": "dim black",
        "accent": "bold magenta",
        "danger": "bold red",
        "success": "bold green",
        "warning": "yellow",
        "info": "blue",
        "background": "on #ffffff",
        "surface": "on #f6f8fa",
        "border": "#d0d7de",
        "text": "#24292f",
        "text-muted": "#656d76",
        "attack": "bold red",
        "defense": "bold green",
        "detection": "bold blue",
        "header": "bold white on #0969da",
        "progress": "#0969da",
        "gauge": "#1a7f37",
        "sparkline": "#8250df",
    }),
    AppTheme.NEON: Theme({
        "primary": "bold magenta",
        "secondary": "dim cyan",
        "accent": "bold yellow",
        "danger": "bold on #ff0000",
        "success": "bold on #00ff00",
        "warning": "bold yellow",
        "info": "bold cyan",
        "background": "on #000000",
        "surface": "on #0a0a0a",
        "border": "#ff00ff",
        "text": "#00ff00",
        "text-muted": "#005500",
        "attack": "bold on #ff0000",
        "defense": "bold on #00ff00",
        "detection": "bold on #0000ff",
        "header": "bold on #ff00ff",
        "progress": "#00ff00",
        "gauge": "#ffff00",
        "sparkline": "#00ffff",
    }),
    AppTheme.MATRIX: Theme({
        "primary": "bold green",
        "secondary": "green",
        "accent": "bold bright_green",
        "danger": "bold red",
        "success": "bold bright_green",
        "warning": "yellow",
        "info": "bright_green",
        "background": "on #000000",
        "surface": "on #0a1a0a",
        "border": "#003300",
        "text": "#00ff00",
        "text-muted": "#005500",
        "attack": "bold red",
        "defense": "bold bright_green",
        "detection": "bold blue",
        "header": "bold on #003300",
        "progress": "#00ff00",
        "gauge": "#00ff00",
        "sparkline": "#00cc00",
    }),
}

DEFAULT_THEME = AppTheme.DARK


def get_theme(theme_name: Optional[str] = None) -> Theme:
    try:
        name = AppTheme(theme_name or "dark")
    except ValueError:
        name = AppTheme.DARK
    return THEMES[name]
