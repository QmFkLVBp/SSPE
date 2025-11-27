"""
terminal_ui.py
Rich-based terminal user interface with:
- Progress bars
- Live event feed
- Colored status messages

Falls back to plain print if Rich not installed.
"""

from typing import Optional, List


class TerminalUI:
    def __init__(self):
        self.use_rich = False
        self.progress = None
        self.task_id = None
        try:
            from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
            self.ProgressClass = Progress
            self.SpinnerColumn = SpinnerColumn
            self.TextColumn = TextColumn
            self.BarColumn = BarColumn
            self.TimeElapsedColumn = TimeElapsedColumn
            self.use_rich = True
        except Exception:
            pass

    def start(self, total_tasks: int):
        if self.use_rich:
            self.progress = self.ProgressClass(
                self.SpinnerColumn(),
                self.TextColumn("[bold blue]{task.description}"),
                self.BarColumn(),
                self.TimeElapsedColumn()
            )
            self.progress.start()
            self.task_id = self.progress.add_task("Initializing...", total=total_tasks, completed=0)
        else:
            print("Starting scan...")

    def update(self, message: str):
        if self.use_rich and self.progress and self.task_id is not None:
            self.progress.update(self.task_id, advance=1, description=message)
        else:
            print(f"[+] {message}")

    def stop(self):
        if self.use_rich and self.progress:
            self.progress.stop()
        else:
            print("Scan complete.")


def colorize(text: str, color: str) -> str:
    """
    Only returns colored text if Rich is installed and running in supported terminal.
    Placeholder: we keep plain text to avoid mixing with TXT report requirements.
    """
    return text