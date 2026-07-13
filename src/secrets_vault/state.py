"""state.toml: salted hashes only — enables staleness detection with the
vault locked, and never stores a value in plaintext."""
import hashlib
import hmac
import secrets as _secrets
from datetime import datetime, timezone
from pathlib import Path

import tomlkit

from . import paths


class StateStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or paths.state_path()
        self._doc = tomlkit.parse(self.path.read_text()) if self.path.exists() else tomlkit.document()
        if "salt" not in self._doc:
            self._doc["salt"] = _secrets.token_hex(16)
            self._flush()

    def _flush(self) -> None:
        self.path.write_text(tomlkit.dumps(self._doc))
        self.path.chmod(0o600)

    def _table(self, key: str):
        if key not in self._doc:
            self._doc[key] = tomlkit.table()
        return self._doc[key]

    def hash_value(self, value: str) -> str:
        salt = bytes.fromhex(str(self._doc["salt"]))
        return hmac.new(salt, value.encode(), hashlib.sha256).hexdigest()

    def set_value_hash(self, secret: str, value: str) -> None:
        self._table("values")[secret] = self.hash_value(value)
        self._flush()

    def value_hash(self, secret: str):
        return self._table("values").get(secret)

    def has_value(self, secret: str) -> bool:
        return self.value_hash(secret) is not None

    def record_push(self, secret: str, target: str) -> None:
        rec = tomlkit.inline_table()
        rec["hash"] = self.value_hash(secret) or ""
        rec["at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._table("pushes")[f"{secret}::{target}"] = rec
        self._flush()

    def pushed_hash(self, secret: str, target: str):
        rec = self._table("pushes").get(f"{secret}::{target}")
        return rec["hash"] if rec else None

    def pushed_at(self, secret: str, target: str):
        rec = self._table("pushes").get(f"{secret}::{target}")
        return rec["at"] if rec else None

    def is_stale(self, secret: str, target: str) -> bool:
        vh = self.value_hash(secret)
        if vh is None:
            return False
        return vh != self.pushed_hash(secret, target)
