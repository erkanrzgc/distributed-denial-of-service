from collections import deque
from typing import Optional

from rich.sparkline import Sparkline as RichSparkline
from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Static
from textual.widget import Widget


class TrafficGraph(Static):
    data: reactive[list] = reactive(list)

    def __init__(self, max_points: int = 60, **kwargs):
        super().__init__(**kwargs)
        self._buffer = deque(maxlen=max_points)
        self._max_points = max_points

    def add_point(self, value: float) -> None:
        self._buffer.append(value)
        self.data = list(self._buffer)
        self.refresh()

    def render(self) -> Text:
        if not self._buffer:
            return Text("─" * 40, style="dim")
        values = list(self._buffer)
        max_val = max(max(values), 1)
        height = 10
        width = min(len(values), 80)

        lines = []
        for row in range(height - 1, -1, -1):
            threshold = (row + 1) / height * max_val
            line_parts = []
            step = max(1, len(values) // width)
            for i in range(0, len(values), step):
                if values[i] >= threshold:
                    line_parts.append("█")
                elif values[i] >= threshold * 0.7:
                    line_parts.append("▄")
                elif values[i] >= threshold * 0.3:
                    line_parts.append("░")
                else:
                    line_parts.append(" ")
            lines.append("".join(line_parts))

        return Text("\n".join(lines), style="cyan")


class Gauge(Static):
    value: reactive[float] = reactive(0.0)
    max_value: reactive[float] = reactive(100.0)
    label: reactive[str] = reactive("")

    def render(self) -> Text:
        pct = min(self.value / self.max_value, 1.0) if self.max_value > 0 else 0
        width = 20
        filled = int(width * pct)
        bar = "█" * filled + "░" * (width - filled)
        style = "green" if pct < 0.7 else ("yellow" if pct < 0.9 else "red")
        text = Text()
        if self.label:
            text.append(f"{self.label}: ", style="dim")
        text.append(bar, style=style)
        text.append(f" {pct*100:.0f}%", style="bold")
        return text


class StatsTable(Static):
    rows: reactive[list] = reactive(list)

    def update_data(self, rows: list[tuple[str, str, str]]) -> None:
        self.rows = rows
        self.refresh()

    def render(self) -> Text:
        text = Text()
        for label, value, style in self.rows:
            text.append(f"{label:20s}", style="dim")
            text.append(f"{value}\n", style=style)
        return text


class LogStream(Static):
    max_lines: int = 10

    def __init__(self, max_lines: int = 10, **kwargs):
        super().__init__(**kwargs)
        self.max_lines = max_lines
        self._lines: deque[str] = deque(maxlen=self.max_lines)

    def add_log(self, line: str, style: str = "") -> None:
        self._lines.append(f"[{style}]{line}[/]" if style else line)
        self.refresh()

    def render(self) -> Text:
        if not self._lines:
            return Text("No logs yet...", style="dim")
        return Text.from_markup("\n".join(self._lines))


class PacketCounter(Static):
    count: reactive[int] = reactive(0)
    rate: reactive[float] = reactive(0.0)
    label: reactive[str] = reactive("Packets")

    def render(self) -> Text:
        text = Text()
        text.append(f"{self.label}: ", style="dim")
        text.append(f"{self.count:,}", style="bold white")
        text.append(f" ({self.rate:,.1f}/s)", style="cyan")
        return text
