"""Modal screens for the TUI: unlock, edit/generate value, one-time reveal, name entry."""
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static

from .. import clipboard
from ..generate import generate


class PassphraseModal(ModalScreen[str | None]):
    def __init__(self, create_mode: bool = False) -> None:
        super().__init__()
        self.create_mode = create_mode

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("Create a vault passphrase:" if self.create_mode else "Vault passphrase:")
            yield Input(password=True, id="passphrase-input")
            if self.create_mode:
                yield Label("Confirm:")
                yield Input(password=True, id="passphrase-confirm")
            yield Button("Unlock", variant="primary", id="ok")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._finish()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self._finish()

    def _finish(self) -> None:
        pw = self.query_one("#passphrase-input", Input).value
        if self.create_mode:
            confirm = self.query_one("#passphrase-confirm", Input).value
            if not pw or pw != confirm:
                self.app.notify("passphrases do not match", severity="error")
                return
        self.dismiss(pw or None)


class EditValueModal(ModalScreen[tuple[str, bool] | None]):
    """Returns (value, generated: bool) or None."""

    def __init__(self, secret_name: str, preset: str, length: int) -> None:
        super().__init__()
        self.secret_name = secret_name
        self.preset = preset
        self.length = length
        self.generated = False
        self._generating = False

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(f"Value for {self.secret_name}:")
            yield Input(password=True, id="value-input")
            yield Label("Confirm:")
            yield Input(password=True, id="value-confirm")
            yield Button("Generate", id="generate")
            yield Button("Save", variant="primary", id="save")
            yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "generate":
            value = generate(self.preset, self.length)
            self._generating = True
            self.query_one("#value-input", Input).value = value
            self.query_one("#value-confirm", Input).value = value
            self._generating = False
            self.generated = True
            return
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        value = self.query_one("#value-input", Input).value
        if not value or value != self.query_one("#value-confirm", Input).value:
            self.app.notify("values are empty or do not match", severity="error")
            return
        self.dismiss((value, self.generated))

    def on_input_changed(self, event: Input.Changed) -> None:
        # a manual edit after Generate means this is no longer a pristine generated value
        if self._generating:
            return
        if event.value and self.generated and event.input.id in ("value-input", "value-confirm"):
            self.generated = False


class GeneratedValueModal(ModalScreen[None]):
    def __init__(self, secret_name: str, value: str) -> None:
        super().__init__()
        self.secret_name = secret_name
        self.value = value

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static(
                f"⚠ This value for [b]{self.secret_name}[/b] will not be shown again "
                "unless you reveal it manually.", id="generated-warning")
            yield Static(self.value, id="generated-value", markup=False)
            yield Button("Copy to clipboard", id="copy")
            yield Button("Close", variant="primary", id="close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "copy":
            ok = clipboard.copy(self.value)
            self.app.notify("copied" if ok else "no clipboard backend available",
                            severity="information" if ok else "warning")
            return
        self.dismiss(None)


class NameModal(ModalScreen[str | None]):
    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("New secret name (use project/KEY for app-scoped):")
            yield Input(id="name-input")
            yield Button("OK", variant="primary", id="ok")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value or None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(self.query_one("#name-input", Input).value or None)
