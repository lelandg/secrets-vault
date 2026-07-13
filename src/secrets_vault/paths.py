"""All config lives under one directory; SECRETS_VAULT_HOME overrides for tests."""
import os
from pathlib import Path

ENV_HOME = "SECRETS_VAULT_HOME"


def config_dir() -> Path:
    override = os.environ.get(ENV_HOME)
    d = Path(override) if override else Path.home() / ".config" / "secrets-vault"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def registry_path() -> Path:
    return config_dir() / "registry.toml"


def state_path() -> Path:
    return config_dir() / "state.toml"


def settings_path() -> Path:
    return config_dir() / "settings.toml"


def logs_dir() -> Path:
    d = config_dir() / "logs"
    d.mkdir(exist_ok=True)
    return d
