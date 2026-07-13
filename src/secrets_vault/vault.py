"""age-format vault via pyrage. The passphrase is only ever read from an
interactive TTY — this is the mechanism that keeps agents away from values."""
import getpass
import json
import os
import sys
from pathlib import Path

import pyrage

from .redact import REDACTOR


class VaultError(Exception):
    pass


class TTYRequiredError(VaultError):
    pass


def read_passphrase(prompt: str = "Vault passphrase: ", confirm: bool = False) -> str:
    if not sys.stdin.isatty():
        raise TTYRequiredError(
            "vault operations require an interactive terminal (agent access to values is disabled by design)")
    pw = getpass.getpass(prompt)
    if not pw:
        raise VaultError("empty passphrase")
    if confirm and getpass.getpass("Confirm passphrase: ") != pw:
        raise VaultError("passphrases do not match")
    return pw


class Vault:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def exists(self) -> bool:
        return self.path.exists()

    def load(self, passphrase: str) -> dict:
        try:
            raw = pyrage.passphrase.decrypt(self.path.read_bytes(), passphrase)
        except Exception:
            raise VaultError("failed to decrypt vault (wrong passphrase?)") from None
        entries = json.loads(raw)
        for entry in entries.values():
            REDACTOR.add(entry["value"])
        return entries

    def save(self, entries: dict, passphrase: str) -> None:
        for entry in entries.values():
            REDACTOR.add(entry["value"])
        encrypted = pyrage.passphrase.encrypt(json.dumps(entries).encode(), passphrase)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_bytes(encrypted)
        tmp.chmod(0o600)
        os.replace(tmp, self.path)
