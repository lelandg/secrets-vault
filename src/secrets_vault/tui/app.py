"""Textual TUI. Values live only in self.entries (in-memory, session-only)."""
from datetime import datetime, timezone

from rich.markup import escape
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import DataTable, Footer, Header, Static

from ..registry import Registry, Secret
from ..settings import load_settings
from ..state import StateStore
from ..vault import Vault, VaultError
from .modals import EditValueModal, GeneratedValueModal, NameModal, PassphraseModal

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
        ("escape", "hide_reveal", "Hide"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.settings = load_settings()
        self.registry = Registry.load()
        self.state = StateStore()
        self.entries: dict | None = None      # None = vault locked
        self.passphrase: str | None = None
        self._revealed = False

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
        self._revealed = False
        self.update_detail()

    async def ensure_unlocked(self) -> bool:
        if self.entries is not None:
            return True
        vault = Vault(self.settings.resolved_vault_path())
        create = not vault.exists()
        pw = await self.push_screen_wait(PassphraseModal(create_mode=create))
        if not pw:
            return False
        try:
            self.entries = vault.load(pw) if not create else {}
        except VaultError as exc:
            self.notify(str(exc), severity="error")
            return False
        self.passphrase = pw
        return True

    def save_vault(self) -> None:
        Vault(self.settings.resolved_vault_path()).save(self.entries, self.passphrase)

    def _store_value(self, name: str, value: str, generated: bool) -> None:
        self.entries[name] = {"value": value,
                              "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        self.save_vault()
        self.state.set_value_hash(name, value)
        if name not in self.registry.secrets:
            self.registry.add_secret(Secret(name=name))
            self.registry.save()
        self.refresh_table()
        if generated:
            self.show_generated(name, value)

    def show_generated(self, name: str, value: str) -> None:
        if not self.settings.show_generated_secrets:
            self.notify(f"stored generated value for {name} (display disabled)")
            return
        self.push_screen(GeneratedValueModal(name, value))

    async def _edit(self, name: str) -> None:
        if not await self.ensure_unlocked():
            return
        result = await self.push_screen_wait(
            EditValueModal(name, self.settings.generate_preset, self.settings.generate_length))
        if result:
            value, generated = result
            self._store_value(name, value, generated)

    def action_edit_secret(self) -> None:
        name = self.selected_secret()
        if name:
            self.run_worker(self._edit(name))

    def action_generate(self) -> None:
        self.action_edit_secret()   # same modal; Generate button inside

    def action_new_secret(self) -> None:
        self.run_worker(self._new())

    async def _new(self) -> None:
        # minimal: prompt for a name via an Input modal reusing EditValueModal pattern
        name = await self.push_screen_wait(NameModal())
        if name:
            await self._edit(name)

    def action_reveal(self) -> None:
        self.run_worker(self._reveal())

    async def _reveal(self) -> None:
        name = self.selected_secret()
        if not name or not await self.ensure_unlocked():
            return
        entry = self.entries.get(name)
        if not entry:
            self.notify("no value set", severity="warning")
            return
        detail = self.query_one("#detail", Static)
        detail.update(f"[b]{escape(name)}[/b]\n\nvalue: {escape(entry['value'])}\n\n(press Escape to hide)")
        self._revealed = True

    def action_hide_reveal(self) -> None:
        if self._revealed:
            self._revealed = False
            self.update_detail()

    def action_push(self) -> None:
        pass

    def action_settings(self) -> None:
        pass


def run() -> None:
    SvApp().run()
