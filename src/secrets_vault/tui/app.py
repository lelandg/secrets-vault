"""Textual TUI. Values live only in self.entries (in-memory, session-only)."""
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import DataTable, Footer, Header, Static

from ..registry import Registry
from ..settings import load_settings
from ..state import StateStore

MASK = "••••••••"


class SvApp(App):
    TITLE = "secrets-vault"
    CSS = """
    #secrets-table { width: 1fr; }
    #detail { width: 1fr; padding: 1; border-left: solid $primary; }
    """
    BINDINGS = [
        ("n", "new_secret", "New"),
        ("e", "edit_secret", "Edit"),
        ("r", "reveal", "Reveal"),
        ("g", "generate", "Generate"),
        ("p", "push", "Push"),
        ("s", "settings", "Settings"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.settings = load_settings()
        self.registry = Registry.load()
        self.state = StateStore()
        self.entries: dict | None = None      # None = vault locked
        self.passphrase: str | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            yield DataTable(id="secrets-table", cursor_type="row")
            yield Static(id="detail")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#secrets-table", DataTable)
        table.add_columns("secret", "value", "targets", "description")
        self.refresh_table()

    def refresh_table(self) -> None:
        table = self.query_one("#secrets-table", DataTable)
        table.clear()
        for name in sorted(self.registry.secrets):
            s = self.registry.secrets[name]
            targets = self.registry.targets_for(name)
            stale = sum(1 for t in targets if self.state.is_stale(name, t.name))
            has_value = "•" if self.state.has_value(name) else "○"
            status = f"{len(targets)} targets" + (f", {stale} stale" if stale else "")
            table.add_row(name, has_value, status, s.description, key=name)
        self.update_detail()

    def selected_secret(self):
        table = self.query_one("#secrets-table", DataTable)
        if table.row_count == 0:
            return None
        row_key = table.coordinate_to_cell_key((table.cursor_row, 0)).row_key
        return row_key.value

    def update_detail(self) -> None:
        name = self.selected_secret()
        detail = self.query_one("#detail", Static)
        if not name:
            detail.update("no secrets yet — press n to add one")
            return
        s = self.registry.secrets[name]
        lines = [f"[b]{name}[/b]", s.description or "(no description)", ""]
        shown = MASK if self.state.has_value(name) else "(no value set)"
        lines.append(f"value: {shown}")
        lines.append("")
        by_project: dict = {}
        for t in self.registry.targets_for(name):
            by_project.setdefault(t.project or "(no project)", []).append(t)
        for proj, ts in sorted(by_project.items()):
            lines.append(f"[b]{proj}[/b]")
            for t in ts:
                mark = "stale" if self.state.is_stale(name, t.name) else "current"
                lines.append(f"  {t.name} [{t.type}] on {t.host} — {mark}")
        detail.update("\n".join(lines))

    def on_data_table_row_highlighted(self, _event) -> None:
        self.update_detail()

    # -- action stubs — wired in Tasks 14-15, declared now so bindings don't
    # crash the app when pressed.
    def action_new_secret(self) -> None:
        pass

    def action_edit_secret(self) -> None:
        pass

    def action_reveal(self) -> None:
        pass

    def action_generate(self) -> None:
        pass

    def action_push(self) -> None:
        pass

    def action_settings(self) -> None:
        pass


def run() -> None:
    SvApp().run()
