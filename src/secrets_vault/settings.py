from dataclasses import asdict, dataclass, field
from pathlib import Path

import tomlkit

from . import paths


@dataclass
class Settings:
    vault_path: str = ""
    project_roots: list = field(default_factory=list)
    generate_preset: str = "urlsafe"
    generate_length: int = 32
    show_generated_secrets: bool = True
    ssh_options: list = field(default_factory=list)

    def resolved_vault_path(self) -> Path:
        return Path(self.vault_path) if self.vault_path else paths.config_dir() / "vault.age"


def load_settings() -> Settings:
    p = paths.settings_path()
    if not p.exists():
        return Settings()
    data = tomlkit.parse(p.read_text())
    known = Settings.__dataclass_fields__
    return Settings(**{k: data[k] for k in data if k in known})


def save_settings(s: Settings) -> None:
    doc = tomlkit.document()
    for k, v in asdict(s).items():
        doc[k] = v
    p = paths.settings_path()
    p.write_text(tomlkit.dumps(doc))
    p.chmod(0o600)
