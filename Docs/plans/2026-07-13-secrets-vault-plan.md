# secrets-vault Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the secrets-vault app from the approved spec (`Docs/plans/2026-07-13-secrets-vault-design.md`): an age-encrypted central secrets registry with an agent-safe `sv` CLI, a Textual TUI with plan→confirm→apply pushes over SSH, secret generation, and a Claude Code import skill.

**Architecture:** One Python package (`src/secrets_vault/`) with pure core modules (registry, state, planner, render, generate, redact) and thin I/O shells (vault via pyrage, executor via ssh subprocess, argparse CLI, Textual TUI). Values are structurally unreachable to agents: TTY-only passphrase, centralized redaction.

**Tech Stack:** Python ≥3.10, textual, tomlkit, pyperclip, pyrage; pytest + pytest-asyncio for tests; system `ssh`.

## Global Constraints

- Repo root: `/mnt/d/Documents/Code/GitHub/secrets-vault` (call it `$ROOT`; use absolute paths, never `cd`).
- Python: `python3`, venv at `$ROOT/.venv_linux` (house rule). All commands below use `$ROOT/.venv_linux/bin/...` explicitly.
- Runtime deps exactly: `textual`, `tomlkit`, `pyperclip`, `pyrage`. Dev deps: `pytest`, `pytest-asyncio`. No others without approval.
- Vault passphrase is read ONLY via `getpass` after an `isatty()` check. Never accept it from flags, env vars, or piped stdin.
- Secret values must never appear in argv, logs, exceptions, or CLI output (sole exception: `sv generate`, and the one-time display in §7.1 of the spec). Everything user-visible that might contain a value goes through `redact()`.
- Config lives under `~/.config/secrets-vault/` (0700); honor `SECRETS_VAULT_HOME` env override (tests rely on it). Files written 0600.
- Tests: every test must pass before commit. Commit after every task with a conventional-commit message ending in the standard co-author trailer used in this repo's history.
- The design spec is the source of truth; if a conflict is found, stop and flag it rather than improvising.

---

### Task 1: Scaffold package, paths, settings

**Files:**
- Create: `pyproject.toml`, `.gitignore`, `src/secrets_vault/__init__.py`, `src/secrets_vault/paths.py`, `src/secrets_vault/settings.py`, `tests/conftest.py`
- Test: `tests/test_settings.py`

**Interfaces:**
- Produces: `paths.config_dir() -> Path`, `paths.registry_path()`, `paths.state_path()`, `paths.settings_path()`, `paths.logs_dir()` (all `-> Path`); `settings.Settings` dataclass (fields: `vault_path: str`, `project_roots: list`, `generate_preset: str`, `generate_length: int`, `show_generated_secrets: bool`, `ssh_options: list`; method `resolved_vault_path() -> Path`); `settings.load_settings() -> Settings`; `settings.save_settings(s: Settings) -> None`. Test fixture `tmp_home` (autouse) pointing `SECRETS_VAULT_HOME` at a tmp dir.

- [ ] **Step 1: Create venv and project skeleton**

```bash
python3 -m venv /mnt/d/Documents/Code/GitHub/secrets-vault/.venv_linux
mkdir -p /mnt/d/Documents/Code/GitHub/secrets-vault/src/secrets_vault /mnt/d/Documents/Code/GitHub/secrets-vault/tests
```

`pyproject.toml`:

```toml
[project]
name = "secrets-vault"
version = "0.1.0"
description = "Central TUI secrets registry: edit once, push everywhere over SSH"
readme = "README.md"
requires-python = ">=3.10"
license = { text = "MIT" }
dependencies = [
    "textual>=0.80",
    "tomlkit>=0.12",
    "pyperclip>=1.9",
    "pyrage>=1.2",
]

[project.optional-dependencies]
dev = ["pytest>=8", "pytest-asyncio>=0.24"]

[project.scripts]
sv = "secrets_vault.cli:main"

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
markers = ["integration: requires `ssh localhost` to work non-interactively"]
```

`.gitignore`:

```gitignore
.venv*/
__pycache__/
*.pyc
dist/
build/
*.egg-info/
# defense in depth: user data never belongs in the clone
.env*
!.env.example
*.age
registry.toml
state.toml
settings.toml
secrets.json
*.key
*.pem
```

`src/secrets_vault/__init__.py`:

```python
__version__ = "0.1.0"
```

- [ ] **Step 2: Install editable + dev deps** (all versions listed are >7 days old; the supply-chain age rule is satisfied)

```bash
/mnt/d/Documents/Code/GitHub/secrets-vault/.venv_linux/bin/pip install -e '/mnt/d/Documents/Code/GitHub/secrets-vault[dev]'
```

Expected: installs textual, tomlkit, pyperclip, pyrage, pytest, pytest-asyncio without error.

- [ ] **Step 3: Write failing tests**

`tests/conftest.py`:

```python
import pytest


@pytest.fixture(autouse=True)
def tmp_home(tmp_path, monkeypatch):
    """Point all config at a throwaway dir so tests never touch real config."""
    home = tmp_path / "svhome"
    monkeypatch.setenv("SECRETS_VAULT_HOME", str(home))
    return home
```

`tests/test_settings.py`:

```python
import stat

from secrets_vault import paths
from secrets_vault.settings import Settings, load_settings, save_settings


def test_config_dir_honors_env_and_is_private(tmp_home):
    d = paths.config_dir()
    assert d == tmp_home
    assert stat.S_IMODE(d.stat().st_mode) == 0o700


def test_defaults_when_no_file():
    s = load_settings()
    assert s.generate_preset == "urlsafe"
    assert s.generate_length == 32
    assert s.show_generated_secrets is True
    assert s.resolved_vault_path() == paths.config_dir() / "vault.age"


def test_round_trip(tmp_home):
    s = Settings(vault_path="/tmp/x.age", project_roots=["/mnt/d/Code"],
                 show_generated_secrets=False)
    save_settings(s)
    loaded = load_settings()
    assert loaded == s
    assert stat.S_IMODE(paths.settings_path().stat().st_mode) == 0o600
```

- [ ] **Step 4: Run tests to verify they fail**

```bash
/mnt/d/Documents/Code/GitHub/secrets-vault/.venv_linux/bin/pytest /mnt/d/Documents/Code/GitHub/secrets-vault/tests/test_settings.py -v
```

Expected: FAIL / collection error — `No module named 'secrets_vault.paths'`.

- [ ] **Step 5: Implement**

`src/secrets_vault/paths.py`:

```python
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
```

`src/secrets_vault/settings.py`:

```python
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
```

- [ ] **Step 6: Run tests to verify they pass**

Same pytest command. Expected: 3 passed.

- [ ] **Step 7: Commit**

```bash
git -C /mnt/d/Documents/Code/GitHub/secrets-vault add -A
git -C /mnt/d/Documents/Code/GitHub/secrets-vault commit -m "feat: scaffold package with paths and settings modules"
```

---

### Task 2: Redaction module

**Files:**
- Create: `src/secrets_vault/redact.py`
- Test: `tests/test_redact.py`

**Interfaces:**
- Produces: `REDACTOR` (module-level `Redactor` instance), `Redactor.add(value: str) -> None`, `Redactor.redact(text: str) -> str`, module function `redact(text: str) -> str`, `get_logger() -> logging.Logger` (file logger into `paths.logs_dir()`, redacting filter installed). Every later module that emits user-visible text about executed work must route it through `redact()`.

- [ ] **Step 1: Write failing tests**

`tests/test_redact.py`:

```python
import logging

from secrets_vault import paths
from secrets_vault.redact import REDACTOR, Redactor, get_logger, redact


def test_registered_values_are_replaced():
    r = Redactor()
    r.add("s3cr3t-value-123")
    assert r.redact("error: s3cr3t-value-123 rejected") == "error: [REDACTED] rejected"


def test_longest_match_first():
    r = Redactor()
    r.add("abc")
    r.add("abcdef")
    assert r.redact("abcdef") == "[REDACTED]"


def test_short_values_not_registered():
    r = Redactor()
    r.add("ab")  # too short: would shred normal text
    assert r.redact("lab report") == "lab report"


def test_module_singleton():
    REDACTOR.add("tok-99887766")
    assert redact("tok-99887766") == "[REDACTED]"


def test_logger_redacts(tmp_home):
    REDACTOR.add("hunter2hunter2")
    log = get_logger()
    log.error("value was hunter2hunter2")
    logging.shutdown()
    text = (paths.logs_dir() / "sv.log").read_text()
    assert "hunter2hunter2" not in text
    assert "[REDACTED]" in text
```

- [ ] **Step 2: Run to verify failure**

```bash
/mnt/d/Documents/Code/GitHub/secrets-vault/.venv_linux/bin/pytest /mnt/d/Documents/Code/GitHub/secrets-vault/tests/test_redact.py -v
```

Expected: FAIL — module missing.

- [ ] **Step 3: Implement**

`src/secrets_vault/redact.py`:

```python
"""Central redaction: every secret value ever seen in-process gets registered
here, and all user-visible/logged text is filtered through redact()."""
import logging

from . import paths

_MIN_LEN = 4


class Redactor:
    def __init__(self) -> None:
        self._values: set[str] = set()

    def add(self, value: str) -> None:
        if value and len(value) >= _MIN_LEN:
            self._values.add(value)

    def redact(self, text: str) -> str:
        for v in sorted(self._values, key=len, reverse=True):
            text = text.replace(v, "[REDACTED]")
        return text


REDACTOR = Redactor()


def redact(text: str) -> str:
    return REDACTOR.redact(text)


class _RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = REDACTOR.redact(record.getMessage())
        record.args = ()
        return True


def get_logger() -> logging.Logger:
    log = logging.getLogger("secrets_vault")
    if not log.handlers:
        handler = logging.FileHandler(paths.logs_dir() / "sv.log")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        handler.addFilter(_RedactingFilter())
        log.addHandler(handler)
        log.setLevel(logging.INFO)
    return log
```

- [ ] **Step 4: Run tests — expect 5 passed.**

- [ ] **Step 5: Commit** — `git -C $ROOT add -A && git -C $ROOT commit -m "feat: central redaction with logging filter"`

---

### Task 3: Secret generation

**Files:**
- Create: `src/secrets_vault/generate.py`
- Test: `tests/test_generate.py`

**Interfaces:**
- Produces: `PRESETS: tuple[str, ...] == ("urlsafe", "hex", "alphanum", "ascii")`; `generate(preset: str = "urlsafe", length: int = 32) -> str`. Length semantics: bytes of entropy for `urlsafe`/`hex`, output characters for `alphanum`/`ascii`. Raises `ValueError` on unknown preset or `length < 1`.

- [ ] **Step 1: Write failing tests**

`tests/test_generate.py`:

```python
import string

import pytest

from secrets_vault.generate import PRESETS, generate


def test_presets_tuple():
    assert PRESETS == ("urlsafe", "hex", "alphanum", "ascii")


def test_hex():
    v = generate("hex", 32)
    assert len(v) == 64
    assert set(v) <= set(string.hexdigits.lower())


def test_alphanum_length_is_chars():
    v = generate("alphanum", 40)
    assert len(v) == 40
    assert v.isalnum()


def test_ascii_avoids_quote_chars():
    v = generate("ascii", 200)
    assert not set(v) & set("\"'\\`$ ")


def test_unique():
    assert generate() != generate()


def test_errors():
    with pytest.raises(ValueError):
        generate("nope")
    with pytest.raises(ValueError):
        generate("hex", 0)
```

- [ ] **Step 2: Run — expect FAIL (module missing).**

- [ ] **Step 3: Implement**

`src/secrets_vault/generate.py`:

```python
"""CSPRNG secret generation (stdlib `secrets`). Length = bytes of entropy
for urlsafe/hex, output characters for alphanum/ascii."""
import secrets
import string

PRESETS = ("urlsafe", "hex", "alphanum", "ascii")

_ALPHANUM = string.ascii_letters + string.digits
# printable ASCII minus space and chars that fight quoting: " ' \ ` $
_ASCII = "".join(c for c in (string.ascii_letters + string.digits + string.punctuation)
                 if c not in "\"'\\`$")


def generate(preset: str = "urlsafe", length: int = 32) -> str:
    if length < 1:
        raise ValueError("length must be >= 1")
    if preset == "urlsafe":
        return secrets.token_urlsafe(length)
    if preset == "hex":
        return secrets.token_hex(length)
    if preset == "alphanum":
        return "".join(secrets.choice(_ALPHANUM) for _ in range(length))
    if preset == "ascii":
        return "".join(secrets.choice(_ASCII) for _ in range(length))
    raise ValueError(f"unknown preset: {preset!r} (choose from {', '.join(PRESETS)})")
```

- [ ] **Step 4: Run tests — expect 6 passed.**

- [ ] **Step 5: Commit** — `"feat: CSPRNG secret generation with presets"`

---

### Task 4: Registry model

**Files:**
- Create: `src/secrets_vault/registry.py`
- Test: `tests/test_registry.py`

**Interfaces:**
- Produces:
  - `Secret` dataclass: `name: str`, `description: str = ""`, `tags: list = []`.
  - `Target` dataclass: `name: str`, `type: str`, `host: str`, `project: str = ""`, `path: str = ""`, `format: str = "dotenv"`, `owner: str = ""`, `mode: str = "600"`, `unit: str = ""`, `command: list = []`, `keys: list = []`, `key_map: dict = {}`, `restart: list = []`; method `all_keys() -> dict[str, str]` (logical name → env-var name; union of `keys` mapped to themselves plus `key_map`).
  - `Registry` dataclass: `secrets: dict[str, Secret]`, `targets: dict[str, Target]`; `Registry.load(path: Path | None = None) -> Registry`; `save(path=None)`; `validate() -> list[str]` (empty = valid); `targets_for(secret_name: str) -> list[Target]`; `add_secret(s: Secret) -> bool` and `add_target(t: Target) -> bool` (idempotent merge; return True if anything changed).
  - `VALID_TYPES = ("env-file", "systemd", "command")`.

- [ ] **Step 1: Write failing tests**

`tests/test_registry.py`:

```python
from secrets_vault.registry import Registry, Secret, Target


def make_target(**kw):
    base = dict(name="t1", type="env-file", host="hermes", path="/opt/app/.env",
                keys=["API_KEY"])
    base.update(kw)
    return Target(**base)


def test_all_keys_merges_key_map():
    t = make_target(keys=["API_KEY"], key_map={"maestro/DATABASE_URL": "DATABASE_URL"})
    assert t.all_keys() == {"API_KEY": "API_KEY", "maestro/DATABASE_URL": "DATABASE_URL"}


def test_round_trip(tmp_path):
    reg = Registry()
    reg.add_secret(Secret(name="API_KEY", description="shared key", tags=["ai"]))
    reg.add_secret(Secret(name="maestro/DATABASE_URL"))
    reg.add_target(make_target(project="maestro",
                               key_map={"maestro/DATABASE_URL": "DATABASE_URL"},
                               restart=["sudo systemctl restart maestro"]))
    p = tmp_path / "registry.toml"
    reg.save(p)
    loaded = Registry.load(p)
    assert loaded.secrets["API_KEY"].tags == ["ai"]
    assert loaded.targets["t1"].restart == ["sudo systemctl restart maestro"]
    assert loaded.targets["t1"].all_keys()["maestro/DATABASE_URL"] == "DATABASE_URL"


def test_targets_for():
    reg = Registry()
    reg.add_secret(Secret(name="API_KEY"))
    reg.add_target(make_target())
    reg.add_target(make_target(name="t2", host="devbox", keys=[],
                               key_map={"API_KEY": "OPENAI_KEY"}))
    assert sorted(t.name for t in reg.targets_for("API_KEY")) == ["t1", "t2"]


def test_add_is_idempotent():
    reg = Registry()
    assert reg.add_secret(Secret(name="A")) is True
    assert reg.add_secret(Secret(name="A")) is False
    assert reg.add_target(make_target()) is True
    assert reg.add_target(make_target()) is False


def test_validate_catches_problems():
    reg = Registry()
    reg.add_target(make_target(type="bogus"))                      # bad type
    reg.add_target(make_target(name="t2", path=""))                # env-file needs path
    reg.add_target(Target(name="t3", type="command", host="local",
                          command=[], keys=["A", "B"]))            # no command, 2 keys
    reg.add_target(Target(name="t4", type="systemd", host="devbox",
                          path="/etc/w/env", keys=["MISSING"]))    # no unit; unknown secret
    errs = "\n".join(reg.validate())
    assert "t1: unknown type" in errs
    assert "t2: env-file target requires 'path'" in errs
    assert "t3: command target requires 'command'" in errs
    assert "t3: command target takes exactly one key" in errs
    assert "t4: systemd target requires 'unit'" in errs
    assert "t4: references unknown secret 'MISSING'" in errs


def test_validate_ok():
    reg = Registry()
    reg.add_secret(Secret(name="API_KEY"))
    reg.add_target(make_target())
    assert reg.validate() == []
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement**

`src/secrets_vault/registry.py`:

```python
"""registry.toml: plaintext structure (secret names + targets), never values."""
from dataclasses import asdict, dataclass, field
from pathlib import Path

import tomlkit

from . import paths

VALID_TYPES = ("env-file", "systemd", "command")


@dataclass
class Secret:
    name: str
    description: str = ""
    tags: list = field(default_factory=list)


@dataclass
class Target:
    name: str
    type: str
    host: str
    project: str = ""
    path: str = ""
    format: str = "dotenv"
    owner: str = ""
    mode: str = "600"
    unit: str = ""
    command: list = field(default_factory=list)
    keys: list = field(default_factory=list)
    key_map: dict = field(default_factory=dict)
    restart: list = field(default_factory=list)

    def all_keys(self) -> dict:
        mapping = {k: k for k in self.keys}
        mapping.update(self.key_map)
        return mapping


@dataclass
class Registry:
    secrets: dict = field(default_factory=dict)
    targets: dict = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | None = None) -> "Registry":
        path = path or paths.registry_path()
        reg = cls()
        if not path.exists():
            return reg
        data = tomlkit.parse(path.read_text())
        for name, body in (data.get("secrets") or {}).items():
            reg.secrets[name] = Secret(name=name,
                                       description=str(body.get("description", "")),
                                       tags=list(body.get("tags", [])))
        fields = Target.__dataclass_fields__
        for name, body in (data.get("targets") or {}).items():
            kwargs = {k: body[k] for k in body if k in fields and k != "name"}
            if "key_map" in kwargs:
                kwargs["key_map"] = dict(kwargs["key_map"])
            for listy in ("command", "keys", "restart"):
                if listy in kwargs:
                    kwargs[listy] = list(kwargs[listy])
            reg.targets[name] = Target(name=name, **kwargs)
        return reg

    def save(self, path: Path | None = None) -> None:
        path = path or paths.registry_path()
        doc = tomlkit.document()
        secrets_tbl = tomlkit.table()
        for name, s in self.secrets.items():
            body = tomlkit.table()
            if s.description:
                body["description"] = s.description
            if s.tags:
                body["tags"] = s.tags
            secrets_tbl[name] = body
        doc["secrets"] = secrets_tbl
        targets_tbl = tomlkit.table()
        for name, t in self.targets.items():
            body = tomlkit.table()
            for k, v in asdict(t).items():
                if k == "name" or v in ("", [], {}):
                    continue
                if k in ("format", "mode") and v == Target.__dataclass_fields__[k].default:
                    continue
                body[k] = v
            targets_tbl[name] = body
        doc["targets"] = targets_tbl
        path.write_text(tomlkit.dumps(doc))
        path.chmod(0o600)

    def validate(self) -> list:
        errs = []
        for t in self.targets.values():
            if t.type not in VALID_TYPES:
                errs.append(f"{t.name}: unknown type {t.type!r}")
                continue
            if not t.host:
                errs.append(f"{t.name}: requires 'host'")
            if t.type in ("env-file", "systemd") and not t.path:
                errs.append(f"{t.name}: {t.type} target requires 'path'")
            if t.type == "systemd" and not t.unit:
                errs.append(f"{t.name}: systemd target requires 'unit'")
            if t.type == "command":
                if not t.command:
                    errs.append(f"{t.name}: command target requires 'command'")
                if len(t.all_keys()) != 1:
                    errs.append(f"{t.name}: command target takes exactly one key")
            for logical in t.all_keys():
                if logical not in self.secrets:
                    errs.append(f"{t.name}: references unknown secret {logical!r}")
        return errs

    def targets_for(self, secret_name: str) -> list:
        return [t for t in self.targets.values() if secret_name in t.all_keys()]

    def add_secret(self, s: Secret) -> bool:
        if s.name in self.secrets:
            return False
        self.secrets[s.name] = s
        return True

    def add_target(self, t: Target) -> bool:
        existing = self.targets.get(t.name)
        if existing == t:
            return False
        self.targets[t.name] = t
        return True
```

- [ ] **Step 4: Run tests — expect 6 passed.**

- [ ] **Step 5: Commit** — `"feat: registry model with validation and idempotent merge"`

---

### Task 5: Push-state store

**Files:**
- Create: `src/secrets_vault/state.py`
- Test: `tests/test_state.py`

**Interfaces:**
- Produces: `StateStore(path: Path | None = None)` with: `hash_value(value: str) -> str` (HMAC-SHA256, per-install random salt persisted in the file), `set_value_hash(secret: str, value: str) -> None`, `value_hash(secret: str) -> str | None`, `has_value(secret: str) -> bool`, `record_push(secret: str, target: str) -> None` (stores current value_hash + UTC ISO timestamp), `pushed_hash(secret: str, target: str) -> str | None`, `pushed_at(secret: str, target: str) -> str | None`, `is_stale(secret: str, target: str) -> bool` (True iff a value hash exists and differs from pushed hash). All mutations persist immediately (file mode 0600).

- [ ] **Step 1: Write failing tests**

`tests/test_state.py`:

```python
from secrets_vault import paths
from secrets_vault.state import StateStore


def test_no_value_means_not_stale():
    st = StateStore()
    assert st.has_value("A") is False
    assert st.is_stale("A", "t1") is False


def test_set_then_stale_then_pushed():
    st = StateStore()
    st.set_value_hash("A", "hunter2hunter2")
    assert st.has_value("A")
    assert st.is_stale("A", "t1") is True          # never pushed
    st.record_push("A", "t1")
    assert st.is_stale("A", "t1") is False
    assert st.pushed_at("A", "t1")                 # timestamp recorded
    st.set_value_hash("A", "newvalue-123")         # rotate
    assert st.is_stale("A", "t1") is True


def test_hash_is_salted_and_not_the_value():
    st = StateStore()
    h = st.hash_value("hunter2hunter2")
    assert "hunter2" not in h and len(h) == 64
    text = paths.state_path().read_text()
    st.set_value_hash("A", "hunter2hunter2")
    assert "hunter2" not in paths.state_path().read_text()


def test_persistence_across_instances():
    StateStore().set_value_hash("A", "v1")
    st2 = StateStore()
    assert st2.has_value("A")
    assert st2.hash_value("v1") == st2.value_hash("A")  # same salt reloaded
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement**

`src/secrets_vault/state.py`:

```python
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
```

- [ ] **Step 4: Run tests — expect 4 passed.**

- [ ] **Step 5: Commit** — `"feat: salted push-state store for lock-free staleness"`

---

### Task 6: Vault (pyrage) + TTY passphrase

**Files:**
- Create: `src/secrets_vault/vault.py`
- Test: `tests/test_vault.py`

**Interfaces:**
- Produces: `VaultError(Exception)`, `TTYRequiredError(VaultError)`; `read_passphrase(prompt: str = "Vault passphrase: ", confirm: bool = False) -> str` (raises `TTYRequiredError` if `sys.stdin.isatty()` is false — THE agent boundary; raises `VaultError` on empty or mismatched confirm); `Vault(path: Path)` with `exists() -> bool`, `load(passphrase: str) -> dict` (name → `{"value": str, "updated_at": iso-str}`; registers every value with `REDACTOR`; raises `VaultError` on bad passphrase), `save(entries: dict, passphrase: str) -> None` (atomic write, 0600, registers values).

- [ ] **Step 1: Write failing tests**

`tests/test_vault.py`:

```python
import pytest

from secrets_vault.redact import redact
from secrets_vault.vault import TTYRequiredError, Vault, VaultError, read_passphrase


def test_round_trip(tmp_path):
    v = Vault(tmp_path / "vault.age")
    assert not v.exists()
    entries = {"API_KEY": {"value": "sk-live-veryverysecret", "updated_at": "2026-07-13T00:00:00+00:00"}}
    v.save(entries, "pw")
    assert v.exists()
    assert v.load("pw") == entries


def test_wrong_passphrase(tmp_path):
    v = Vault(tmp_path / "vault.age")
    v.save({"A": {"value": "somevalue123", "updated_at": "x"}}, "right")
    with pytest.raises(VaultError):
        v.load("wrong")


def test_file_is_age_format_not_plaintext(tmp_path):
    v = Vault(tmp_path / "vault.age")
    v.save({"A": {"value": "plainlyvisible99", "updated_at": "x"}}, "pw")
    raw = (tmp_path / "vault.age").read_bytes()
    assert b"plainlyvisible99" not in raw
    assert raw.startswith(b"age-encryption.org/v1")


def test_load_registers_redaction(tmp_path):
    v = Vault(tmp_path / "vault.age")
    v.save({"A": {"value": "leakable-value-42", "updated_at": "x"}}, "pw")
    v.load("pw")
    assert redact("oops leakable-value-42") == "oops [REDACTED]"


def test_passphrase_requires_tty(monkeypatch):
    import sys
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(TTYRequiredError):
        read_passphrase()


def test_passphrase_confirm_mismatch(monkeypatch):
    import sys
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    answers = iter(["one-passphrase", "different"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    with pytest.raises(VaultError):
        read_passphrase(confirm=True)
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement**

`src/secrets_vault/vault.py`:

```python
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
```

- [ ] **Step 4: Run tests — expect 6 passed.**

- [ ] **Step 5: Commit** — `"feat: pyrage vault with TTY-only passphrase boundary"`

---

### Task 7: Env-file rendering

**Files:**
- Create: `src/secrets_vault/render.py`
- Test: `tests/test_render.py`

**Interfaces:**
- Produces: `render(env: dict[str, str], fmt: str = "dotenv") -> str`. `dotenv`: `KEY=value` unquoted when value is plain (alnum plus `._:/@+=-`), double-quoted with `\\` and `\"` escaping otherwise. `env`: always `KEY="value"` (escaped). Keys sorted; header comment `# managed by secrets-vault`; trailing newline. Raises `ValueError` on unknown fmt.

- [ ] **Step 1: Write failing tests**

`tests/test_render.py`:

```python
import pytest

from secrets_vault.render import render


def test_dotenv_plain_and_quoted():
    out = render({"B_KEY": 'has "quotes" and spaces', "A_KEY": "simple-123"})
    lines = out.splitlines()
    assert lines[0] == "# managed by secrets-vault"
    assert lines[1] == "A_KEY=simple-123"                       # sorted, unquoted
    assert lines[2] == 'B_KEY="has \\"quotes\\" and spaces"'
    assert out.endswith("\n")


def test_env_format_always_quotes():
    out = render({"A": "simple"}, fmt="env")
    assert 'A="simple"' in out


def test_backslash_escaped():
    out = render({"A": "back\\slash"})
    assert 'A="back\\\\slash"' in out


def test_unknown_format():
    with pytest.raises(ValueError):
        render({}, fmt="yaml")
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement**

`src/secrets_vault/render.py`:

```python
"""Render env dicts to dotenv / env-file text. Deterministic: sorted keys."""
import re

_PLAIN = re.compile(r"^[A-Za-z0-9._:/@+=-]+$")


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _line(key: str, value: str, fmt: str) -> str:
    if fmt == "env":
        return f'{key}="{_escape(value)}"'
    if fmt == "dotenv":
        if _PLAIN.match(value):
            return f"{key}={value}"
        return f'{key}="{_escape(value)}"'
    raise ValueError(f"unknown format: {fmt!r}")


def render(env: dict, fmt: str = "dotenv") -> str:
    if fmt not in ("dotenv", "env"):
        raise ValueError(f"unknown format: {fmt!r}")
    lines = ["# managed by secrets-vault"]
    for key in sorted(env):
        lines.append(_line(key, env[key], fmt))
    return "\n".join(lines) + "\n"
```

- [ ] **Step 4: Run tests — expect 4 passed.**

- [ ] **Step 5: Commit** — `"feat: dotenv/env rendering with safe quoting"`

---

### Task 8: Planner (pure)

**Files:**
- Create: `src/secrets_vault/planner.py`
- Test: `tests/test_planner.py`

**Interfaces:**
- Consumes: `Registry`/`Target` (Task 4), `StateStore` (Task 5).
- Produces: `Step` dataclass (`kind: str` in `("write-file", "command", "restart")`, `target: str`, `host: str`, `detail: dict`); `Plan` dataclass (`steps: list[Step]`, `by_host() -> dict[str, list[Step]]`, `is_empty() -> bool`); `build_plan(registry, state, secrets=None, targets=None, force=False) -> Plan`.
  - `detail` for `write-file`: `path`, `format`, `owner`, `mode`, `env_keys` (dict logical→env-var, only secrets WITH values), `stale` (list of logical names triggering the write), `missing` (list of logical names with no value yet).
  - `detail` for `command`: `argv: list`, `stdin_secret: str`.
  - `detail` for `restart`: `cmd: str`.
  - A target contributes steps iff at least one of its (filter-matching) secrets has a value and is stale (or `force` and has a value). Systemd targets append `systemctl restart <unit>` after any configured `restart` commands. Restart steps follow their target's write/command step, same order.

- [ ] **Step 1: Write failing tests**

`tests/test_planner.py`:

```python
from secrets_vault.planner import build_plan
from secrets_vault.registry import Registry, Secret, Target
from secrets_vault.state import StateStore


def setup():
    reg = Registry()
    reg.add_secret(Secret(name="API_KEY"))
    reg.add_secret(Secret(name="maestro/DATABASE_URL"))
    reg.add_secret(Secret(name="EMPTY_ONE"))
    reg.add_target(Target(name="hermes-maestro", type="env-file", host="hermes",
                          project="maestro", path="/opt/maestro/.env",
                          keys=["API_KEY", "EMPTY_ONE"],
                          key_map={"maestro/DATABASE_URL": "DATABASE_URL"},
                          restart=["sudo systemctl restart maestro"]))
    reg.add_target(Target(name="worker", type="systemd", host="devbox",
                          unit="worker.service", path="/etc/worker/env",
                          keys=["API_KEY"]))
    reg.add_target(Target(name="gh", type="command", host="local",
                          command=["gh", "secret", "set", "API_KEY"],
                          keys=["API_KEY"]))
    st = StateStore()
    st.set_value_hash("API_KEY", "v1")
    st.set_value_hash("maestro/DATABASE_URL", "postgres://x")
    return reg, st


def test_all_stale_initially():
    reg, st = setup()
    plan = build_plan(reg, st)
    kinds = [(s.kind, s.target) for s in plan.steps]
    assert ("write-file", "hermes-maestro") in kinds
    assert ("restart", "hermes-maestro") in kinds
    assert ("write-file", "worker") in kinds
    assert ("command", "gh") in kinds
    wf = next(s for s in plan.steps if s.target == "hermes-maestro" and s.kind == "write-file")
    assert wf.detail["env_keys"] == {"API_KEY": "API_KEY", "maestro/DATABASE_URL": "DATABASE_URL"}
    assert wf.detail["missing"] == ["EMPTY_ONE"]
    sysd = [s for s in plan.steps if s.target == "worker" and s.kind == "restart"]
    assert sysd[0].detail["cmd"] == "systemctl restart worker.service"


def test_fresh_targets_skipped():
    reg, st = setup()
    for t in ("hermes-maestro", "worker", "gh"):
        st.record_push("API_KEY", t)
    st.record_push("maestro/DATABASE_URL", "hermes-maestro")
    assert build_plan(reg, st).is_empty()
    assert not build_plan(reg, st, force=True).is_empty()


def test_secret_filter():
    reg, st = setup()
    plan = build_plan(reg, st, secrets=["maestro/DATABASE_URL"])
    assert {s.target for s in plan.steps} == {"hermes-maestro"}


def test_target_filter_and_by_host():
    reg, st = setup()
    plan = build_plan(reg, st, targets=["worker"])
    assert set(plan.by_host()) == {"devbox"}


def test_restart_follows_write():
    reg, st = setup()
    steps = [s for s in build_plan(reg, st).steps if s.target == "hermes-maestro"]
    assert [s.kind for s in steps] == ["write-file", "restart"]
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement**

`src/secrets_vault/planner.py`:

```python
"""Pure plan computation: no I/O, no vault access — works with the vault locked."""
from dataclasses import dataclass, field


@dataclass
class Step:
    kind: str        # "write-file" | "command" | "restart"
    target: str
    host: str
    detail: dict


@dataclass
class Plan:
    steps: list = field(default_factory=list)

    def by_host(self) -> dict:
        grouped: dict = {}
        for s in self.steps:
            grouped.setdefault(s.host, []).append(s)
        return grouped

    def is_empty(self) -> bool:
        return not self.steps


def build_plan(registry, state, secrets=None, targets=None, force=False) -> Plan:
    plan = Plan()
    for t in registry.targets.values():
        if targets and t.name not in targets:
            continue
        keys = t.all_keys()  # logical -> env var
        candidates = [s for s in keys if not secrets or s in secrets]
        if not candidates:
            continue
        stale = [s for s in candidates if state.has_value(s)
                 and (force or state.is_stale(s, t.name))]
        if not stale:
            continue
        if t.type in ("env-file", "systemd"):
            with_values = {s: keys[s] for s in keys if state.has_value(s)}
            missing = [s for s in keys if not state.has_value(s)]
            plan.steps.append(Step("write-file", t.name, t.host, {
                "path": t.path, "format": t.format, "owner": t.owner,
                "mode": t.mode, "env_keys": with_values,
                "stale": stale, "missing": missing,
            }))
            restarts = list(t.restart)
            if t.type == "systemd":
                restarts.append(f"systemctl restart {t.unit}")
        elif t.type == "command":
            plan.steps.append(Step("command", t.name, t.host, {
                "argv": list(t.command), "stdin_secret": stale[0],
            }))
            restarts = list(t.restart)
        else:
            continue
        for cmd in restarts:
            plan.steps.append(Step("restart", t.name, t.host, {"cmd": cmd}))
    return plan
```

- [ ] **Step 4: Run tests — expect 5 passed.**

- [ ] **Step 5: Commit** — `"feat: pure push planner with staleness and filters"`

---

### Task 9: Executor

**Files:**
- Create: `src/secrets_vault/executor.py`
- Test: `tests/test_executor.py`

**Interfaces:**
- Consumes: `Plan`/`Step` (Task 8), `render` (Task 7), `redact` (Task 2).
- Produces: `StepResult` dataclass (`step: Step`, `ok: bool`, `message: str`); `Executor(get_value: Callable[[str], str], ssh_options: list | None = None, runner=subprocess.run)`; `Executor.execute(plan: Plan, dry_run: bool = False) -> list[StepResult]`. Behavior: `host == "local"` writes files directly (temp + `os.replace`, chmod) and runs commands locally; remote uses `ssh -o BatchMode=yes [ssh_options] <host> <cmd>` with content/value on stdin; restart steps for a target are skipped (ok=False, message "skipped: earlier step failed") if a prior step for the same target failed; all failure messages pass through `redact()`; one failing host never raises.

- [ ] **Step 1: Write failing tests**

`tests/test_executor.py`:

```python
import subprocess
from pathlib import Path

from secrets_vault.executor import Executor, StepResult
from secrets_vault.planner import Plan, Step

VALUES = {"API_KEY": "sk-live-secret-xyz", "TOK": "tok-abc-123456"}


class FakeRunner:
    """Records calls; scripted returncodes."""
    def __init__(self, fail_on=()):
        self.calls = []
        self.fail_on = fail_on

    def __call__(self, argv, input=None, capture_output=True, timeout=None):
        self.calls.append((argv, input))
        rc = 1 if any(f in " ".join(argv) for f in self.fail_on) else 0
        return subprocess.CompletedProcess(argv, rc, stdout=b"", stderr=b"boom sk-live-secret-xyz" if rc else b"")


def wf_step(host="hermes", path="/opt/app/.env"):
    return Step("write-file", "t1", host, {
        "path": path, "format": "dotenv", "owner": "", "mode": "600",
        "env_keys": {"API_KEY": "API_KEY"}, "stale": ["API_KEY"], "missing": []})


def test_remote_write_goes_over_ssh_stdin():
    r = FakeRunner()
    ex = Executor(VALUES.__getitem__, runner=r)
    results = ex.execute(Plan([wf_step()]))
    assert results[0].ok
    argv, stdin = r.calls[0]
    assert argv[:3] == ["ssh", "-o", "BatchMode=yes"]
    assert argv[3] == "hermes"
    assert "umask 077" in argv[4] and "/opt/app/.env" in argv[4]
    assert b"API_KEY=sk-live-secret-xyz" in stdin
    assert "sk-live" not in " ".join(argv)          # value never in argv


def test_local_write(tmp_path):
    p = tmp_path / "app.env"
    ex = Executor(VALUES.__getitem__, runner=FakeRunner())
    results = ex.execute(Plan([wf_step(host="local", path=str(p))]))
    assert results[0].ok
    assert "API_KEY=sk-live-secret-xyz" in p.read_text()
    assert (p.stat().st_mode & 0o777) == 0o600


def test_command_value_on_stdin_local():
    r = FakeRunner()
    ex = Executor(VALUES.__getitem__, runner=r)
    step = Step("command", "gh", "local", {"argv": ["gh", "secret", "set", "TOK"], "stdin_secret": "TOK"})
    ex.execute(Plan([step]))
    argv, stdin = r.calls[0]
    assert argv == ["gh", "secret", "set", "TOK"]
    assert stdin == b"tok-abc-123456"


def test_failure_skips_restart_and_redacts():
    r = FakeRunner(fail_on=["umask"])
    ex = Executor(VALUES.__getitem__, runner=r)
    restart = Step("restart", "t1", "hermes", {"cmd": "systemctl restart app"})
    results = ex.execute(Plan([wf_step(), restart]))
    assert results[0].ok is False
    assert "sk-live-secret-xyz" not in results[0].message   # redacted stderr
    assert results[1].ok is False
    assert results[1].message == "skipped: earlier step failed"


def test_dry_run_touches_nothing():
    r = FakeRunner()
    ex = Executor(VALUES.__getitem__, runner=r)
    results = ex.execute(Plan([wf_step()]), dry_run=True)
    assert results[0].ok and results[0].message == "dry-run"
    assert r.calls == []
```

Note: `test_failure_skips_restart_and_redacts` requires the executor to register values with `REDACTOR` implicitly? No — `Vault.load` does that in real flows. In this test, register manually at top of the test:

```python
def test_failure_skips_restart_and_redacts():
    from secrets_vault.redact import REDACTOR
    REDACTOR.add(VALUES["API_KEY"])
    ...
```

(Include that line in the actual test file.)

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement**

`src/secrets_vault/executor.py`:

```python
"""Executes a Plan. Values travel only via stdin — never argv, never temp files."""
import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .planner import Plan, Step
from .redact import redact
from .render import render


@dataclass
class StepResult:
    step: Step
    ok: bool
    message: str


class Executor:
    def __init__(self, get_value, ssh_options=None, runner=subprocess.run) -> None:
        self.get_value = get_value
        self.ssh_options = list(ssh_options or [])
        self.runner = runner

    def execute(self, plan: Plan, dry_run: bool = False) -> list:
        results = []
        failed_targets = set()
        for step in plan.steps:
            if step.kind == "restart" and step.target in failed_targets:
                results.append(StepResult(step, False, "skipped: earlier step failed"))
                continue
            if dry_run:
                results.append(StepResult(step, True, "dry-run"))
                continue
            try:
                ok, message = self._run_step(step)
            except Exception as exc:  # noqa: BLE001 - report, never crash the run
                ok, message = False, redact(f"{type(exc).__name__}: {exc}")
            if not ok:
                failed_targets.add(step.target)
            results.append(StepResult(step, ok, message))
        return results

    # -- steps ------------------------------------------------------------
    def _run_step(self, step: Step):
        if step.kind == "write-file":
            return self._write_file(step)
        if step.kind == "command":
            return self._command(step)
        if step.kind == "restart":
            return self._shell(step.host, step.detail["cmd"], timeout=120)
        return False, f"unknown step kind {step.kind!r}"

    def _write_file(self, step: Step):
        d = step.detail
        env = {envvar: self.get_value(logical) for logical, envvar in d["env_keys"].items()}
        content = render(env, d["format"])
        if step.host == "local":
            p = Path(d["path"]).expanduser()
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_name(p.name + ".svtmp")
            tmp.write_text(content)
            tmp.chmod(int(d["mode"], 8))
            os.replace(tmp, p)
            return True, f"wrote {p}"
        q = shlex.quote(d["path"])
        remote = (f"umask 077 && cat > {q}.svtmp && mv {q}.svtmp {q}"
                  f" && chmod {shlex.quote(d['mode'])} {q}")
        if d["owner"]:
            remote += f" && chown {shlex.quote(d['owner'])} {q}"
        cp = self.runner(self._ssh(step.host, remote), input=content.encode(),
                         capture_output=True, timeout=30)
        if cp.returncode != 0:
            return False, redact(cp.stderr.decode(errors="replace").strip() or "ssh failed")
        return True, f"wrote {step.host}:{d['path']}"

    def _command(self, step: Step):
        value = self.get_value(step.detail["stdin_secret"])
        argv = list(step.detail["argv"])
        if step.host == "local":
            cp = self.runner(argv, input=value.encode(), capture_output=True, timeout=60)
        else:
            remote = " ".join(shlex.quote(a) for a in argv)
            cp = self.runner(self._ssh(step.host, remote), input=value.encode(),
                             capture_output=True, timeout=60)
        if cp.returncode != 0:
            return False, redact(cp.stderr.decode(errors="replace").strip() or "command failed")
        return True, "ok"

    def _shell(self, host: str, cmd: str, timeout: int):
        if host == "local":
            cp = self.runner(["bash", "-c", cmd], capture_output=True, timeout=timeout)
        else:
            cp = self.runner(self._ssh(host, cmd), capture_output=True, timeout=timeout)
        if cp.returncode != 0:
            return False, redact(cp.stderr.decode(errors="replace").strip() or "failed")
        return True, "ok"

    def _ssh(self, host: str, remote_cmd: str) -> list:
        return ["ssh", "-o", "BatchMode=yes", *self.ssh_options, host, remote_cmd]
```

- [ ] **Step 4: Run tests — expect 5 passed.**

- [ ] **Step 5: Commit** — `"feat: plan executor with ssh stdin transport and per-target isolation"`

---

### Task 10: Clipboard helper

**Files:**
- Create: `src/secrets_vault/clipboard.py`
- Test: `tests/test_clipboard.py`

**Interfaces:**
- Produces: `copy(text: str) -> bool` — True if a backend accepted the text. Tries `pyperclip.copy`; on any exception falls back to `clip.exe` (WSL) if present on PATH; returns False when neither works. Never raises.

- [ ] **Step 1: Write failing tests**

`tests/test_clipboard.py`:

```python
import secrets_vault.clipboard as cb


def test_pyperclip_path(monkeypatch):
    sent = {}
    monkeypatch.setattr(cb, "_pyperclip_copy", lambda t: sent.setdefault("v", t))
    assert cb.copy("hello") is True
    assert sent["v"] == "hello"


def test_wsl_fallback(monkeypatch):
    def boom(_):
        raise RuntimeError("no display")
    calls = {}
    monkeypatch.setattr(cb, "_pyperclip_copy", boom)
    monkeypatch.setattr(cb.shutil, "which", lambda n: "/mnt/c/Windows/System32/clip.exe")
    monkeypatch.setattr(cb.subprocess, "run",
                        lambda argv, **kw: calls.setdefault("argv", argv))
    assert cb.copy("hello") is True
    assert calls["argv"] == ["/mnt/c/Windows/System32/clip.exe"]


def test_no_backend(monkeypatch):
    def boom(_):
        raise RuntimeError
    monkeypatch.setattr(cb, "_pyperclip_copy", boom)
    monkeypatch.setattr(cb.shutil, "which", lambda n: None)
    assert cb.copy("hello") is False
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement**

`src/secrets_vault/clipboard.py`:

```python
"""Best-effort clipboard: pyperclip, then WSL clip.exe. Never raises."""
import shutil
import subprocess


def _pyperclip_copy(text: str) -> None:
    import pyperclip
    pyperclip.copy(text)


def copy(text: str) -> bool:
    try:
        _pyperclip_copy(text)
        return True
    except Exception:
        pass
    clip = shutil.which("clip.exe")
    if clip:
        try:
            subprocess.run([clip], input=text.encode(), check=True, timeout=5)
            return True
        except Exception:
            return False
    return False
```

- [ ] **Step 4: Run tests — expect 3 passed.**

- [ ] **Step 5: Commit** — `"feat: clipboard helper with WSL fallback"`

---

### Task 11: CLI — agent-safe read surface + generate + config

**Files:**
- Create: `src/secrets_vault/cli.py`
- Test: `tests/test_cli_read.py`

**Interfaces:**
- Consumes: everything from Tasks 1–10.
- Produces: `main(argv: list | None = None) -> int` (registered as the `sv` script). Subcommands in this task:
  - `sv list [--json]` — table/JSON of secrets: name, description, has_value, #targets, #stale targets.
  - `sv show <secret> [--json]` — description, tags, has_value, consuming targets grouped by project with per-target staleness + last-push time. Values NEVER printed.
  - `sv targets [--json]` — name, type, host, project, #keys.
  - `sv plan [--secret S ...] [--target T ...] [--force] [--json]` — human tree by host, or JSON steps (details included; no values anywhere).
  - `sv generate [--preset P] [--length N]` — prints ONE line: the generated value (deliberate redaction exemption).
  - `sv config check` — registry validation errors + per-host `ssh -o BatchMode=yes <host> true` probe (reports ok/fail per host); exit 1 on any problem.
  - `sv config set <key> <value>` — updates settings.toml; `show_generated_secrets false` requires an interactive TTY and typed `YES` acknowledgment.
  - Also produces internal helpers reused by Task 12: `_load_all() -> tuple[Settings, Registry, StateStore]` and `_print_plan(plan, state) -> None`.
- Unknown command / validation errors → exit code 2; operational failures → 1; success → 0.

- [ ] **Step 1: Write failing tests**

`tests/test_cli_read.py`:

```python
import json

from secrets_vault.cli import main
from secrets_vault.registry import Registry, Secret, Target
from secrets_vault.state import StateStore


def seed():
    reg = Registry()
    reg.add_secret(Secret(name="API_KEY", description="shared key"))
    reg.add_secret(Secret(name="maestro/DATABASE_URL"))
    reg.add_target(Target(name="hermes-maestro", type="env-file", host="hermes",
                          project="maestro", path="/opt/maestro/.env",
                          keys=["API_KEY"],
                          key_map={"maestro/DATABASE_URL": "DATABASE_URL"}))
    reg.save()
    st = StateStore()
    st.set_value_hash("API_KEY", "sk-live-notshown")
    return reg, st


def test_list_json(capsys):
    seed()
    assert main(["list", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    row = next(r for r in rows if r["name"] == "API_KEY")
    assert row["has_value"] is True and row["targets"] == 1 and row["stale"] == 1
    assert "sk-live-notshown" not in json.dumps(rows)


def test_show_groups_by_project(capsys):
    seed()
    assert main(["show", "API_KEY"]) == 0
    out = capsys.readouterr().out
    assert "maestro" in out and "hermes-maestro" in out and "stale" in out
    assert "sk-live" not in out


def test_show_unknown_secret(capsys):
    seed()
    assert main(["show", "NOPE"]) == 2


def test_plan_json_has_no_values(capsys):
    seed()
    assert main(["plan", "--json"]) == 0
    steps = json.loads(capsys.readouterr().out)
    assert steps[0]["kind"] == "write-file"
    assert "sk-live" not in json.dumps(steps)


def test_generate_prints_value(capsys):
    assert main(["generate", "--preset", "hex", "--length", "16"]) == 0
    out = capsys.readouterr().out.strip()
    assert len(out) == 32


def test_config_set_and_check(capsys, tmp_home):
    seed()
    assert main(["config", "set", "generate_length", "48"]) == 0
    from secrets_vault.settings import load_settings
    assert load_settings().generate_length == 48


def test_config_set_display_off_requires_tty(monkeypatch):
    import sys
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    assert main(["config", "set", "show_generated_secrets", "false"]) == 2
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement**

`src/secrets_vault/cli.py`:

```python
"""`sv` CLI. The read surface (list/show/targets/plan/config check) is
agent-safe: values are structurally absent. Value operations (set/apply)
live behind read_passphrase()'s TTY requirement — see Task 12."""
import argparse
import json
import subprocess
import sys

from .generate import PRESETS, generate
from .planner import build_plan
from .redact import get_logger
from .registry import Registry
from .settings import Settings, load_settings, save_settings
from .state import StateStore


def _load_all():
    return load_settings(), Registry.load(), StateStore()


# -- helpers ---------------------------------------------------------------

def _secret_rows(reg, st):
    rows = []
    for name, s in sorted(reg.secrets.items()):
        targets = reg.targets_for(name)
        rows.append({
            "name": name, "description": s.description, "tags": s.tags,
            "has_value": st.has_value(name), "targets": len(targets),
            "stale": sum(1 for t in targets if st.is_stale(name, t.name)),
        })
    return rows


def _print_plan(plan, state):
    if plan.is_empty():
        print("Nothing to push — all targets current.")
        return
    for host, steps in plan.by_host().items():
        print(f"{host}:")
        for s in steps:
            if s.kind == "write-file":
                extra = f" (stale: {', '.join(s.detail['stale'])})"
                if s.detail["missing"]:
                    extra += f" [no value yet: {', '.join(s.detail['missing'])}]"
                print(f"  write {s.detail['path']}{extra}")
            elif s.kind == "command":
                print(f"  run   {' '.join(s.detail['argv'])}  <- {s.detail['stdin_secret']}")
            else:
                print(f"  exec  {s.detail['cmd']}")


# -- subcommands -----------------------------------------------------------

def _cmd_list(args):
    _, reg, st = _load_all()
    rows = _secret_rows(reg, st)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    for r in rows:
        mark = "•" if r["has_value"] else "○"
        print(f"{mark} {r['name']:<40} targets={r['targets']} stale={r['stale']}  {r['description']}")
    return 0


def _cmd_show(args):
    _, reg, st = _load_all()
    s = reg.secrets.get(args.secret)
    if s is None:
        print(f"unknown secret: {args.secret}", file=sys.stderr)
        return 2
    targets = reg.targets_for(s.name)
    by_project = {}
    for t in targets:
        by_project.setdefault(t.project or "(no project)", []).append(t)
    data = {
        "name": s.name, "description": s.description, "tags": s.tags,
        "has_value": st.has_value(s.name),
        "projects": {
            proj: [{"target": t.name, "type": t.type, "host": t.host,
                    "stale": st.is_stale(s.name, t.name),
                    "pushed_at": st.pushed_at(s.name, t.name)} for t in ts]
            for proj, ts in sorted(by_project.items())
        },
    }
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    print(f"{s.name} — {s.description or '(no description)'}")
    print(f"value set: {'yes' if data['has_value'] else 'no'}")
    for proj, ts in data["projects"].items():
        print(f"  {proj}:")
        for t in ts:
            status = "stale" if t["stale"] else f"current (pushed {t['pushed_at'] or 'never'})"
            print(f"    {t['target']} [{t['type']}] on {t['host']} — {status}")
    return 0


def _cmd_targets(args):
    _, reg, _ = _load_all()
    rows = [{"name": t.name, "type": t.type, "host": t.host,
             "project": t.project, "keys": len(t.all_keys())}
            for t in sorted(reg.targets.values(), key=lambda t: t.name)]
    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        for r in rows:
            print(f"{r['name']:<30} {r['type']:<9} host={r['host']:<12} project={r['project']} keys={r['keys']}")
    return 0


def _cmd_plan(args):
    _, reg, st = _load_all()
    plan = build_plan(reg, st, secrets=args.secret or None,
                      targets=args.target or None, force=args.force)
    if args.json:
        print(json.dumps([{"kind": s.kind, "target": s.target, "host": s.host,
                           "detail": s.detail} for s in plan.steps], indent=2))
    else:
        _print_plan(plan, st)
    return 0


def _cmd_generate(args):
    print(generate(args.preset, args.length))
    return 0


def _cmd_config_check(args):
    _, reg, _ = _load_all()
    errs = reg.validate()
    for e in errs:
        print(f"registry: {e}", file=sys.stderr)
    hosts = sorted({t.host for t in reg.targets.values() if t.host and t.host != "local"})
    failed = bool(errs)
    for h in hosts:
        cp = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", h, "true"],
                            capture_output=True)
        ok = cp.returncode == 0
        print(f"ssh {h}: {'ok' if ok else 'FAILED'}")
        failed = failed or not ok
    if not errs:
        print("registry: ok")
    return 1 if failed else 0


def _cmd_config_set(args):
    s = load_settings()
    key, value = args.key, args.value
    if key not in Settings.__dataclass_fields__:
        print(f"unknown setting: {key}", file=sys.stderr)
        return 2
    current = getattr(s, key)
    if isinstance(current, bool):
        parsed = value.lower() in ("true", "1", "yes")
    elif isinstance(current, int):
        parsed = int(value)
    elif isinstance(current, list):
        parsed = [v for v in value.split(",") if v]
    else:
        parsed = value
    if key == "show_generated_secrets" and parsed is False:
        if not sys.stdin.isatty():
            print("disabling the one-time display requires an interactive terminal", file=sys.stderr)
            return 2
        print("WARNING: generated values will NOT be displayed anywhere after this.")
        print("They will only be retrievable via manual reveal in the TUI.")
        if input("Type YES to confirm: ").strip() != "YES":
            print("aborted")
            return 1
    setattr(s, key, parsed)
    save_settings(s)
    print(f"{key} = {parsed}")
    return 0


# -- entry point -----------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sv", description="secrets-vault")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("list", help="list secrets (values never shown)")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(fn=_cmd_list)

    sp = sub.add_parser("show", help="show a secret's consumers, grouped by project")
    sp.add_argument("secret")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(fn=_cmd_show)

    sp = sub.add_parser("targets", help="list targets")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(fn=_cmd_targets)

    sp = sub.add_parser("plan", help="what would be pushed where")
    sp.add_argument("--secret", action="append")
    sp.add_argument("--target", action="append")
    sp.add_argument("--force", action="store_true")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(fn=_cmd_plan)

    sp = sub.add_parser("generate", help="generate a random secret and print it")
    sp.add_argument("--preset", choices=PRESETS, default=None)
    sp.add_argument("--length", type=int, default=None)
    sp.set_defaults(fn=_cmd_generate)

    sp = sub.add_parser("config", help="configuration")
    csub = sp.add_subparsers(dest="config_cmd", required=True)
    cc = csub.add_parser("check", help="validate registry and probe SSH hosts")
    cc.set_defaults(fn=_cmd_config_check)
    cs = csub.add_parser("set", help="set a settings.toml key")
    cs.add_argument("key")
    cs.add_argument("value")
    cs.set_defaults(fn=_cmd_config_set)
    return p


def main(argv=None) -> int:
    settings = load_settings()
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "preset", None) is None and hasattr(args, "preset"):
        args.preset = settings.generate_preset
    if getattr(args, "length", None) is None and hasattr(args, "length"):
        args.length = settings.generate_length
    try:
        return args.fn(args)
    except Exception as exc:  # noqa: BLE001 - log redacted, fail cleanly
        from .redact import redact
        get_logger().exception("command failed")
        print(redact(f"error: {exc}"), file=sys.stderr)
        return 1
```

- [ ] **Step 4: Run — expect 7 passed** (`tests/test_cli_read.py`), then full suite:

```bash
/mnt/d/Documents/Code/GitHub/secrets-vault/.venv_linux/bin/pytest /mnt/d/Documents/Code/GitHub/secrets-vault/tests -v
```

- [ ] **Step 5: Commit** — `"feat: agent-safe sv CLI (list/show/targets/plan/generate/config)"`

---

### Task 12: CLI — set / import / apply (TTY-gated value operations)

**Files:**
- Modify: `src/secrets_vault/cli.py` (add subcommands to `build_parser()` and their functions)
- Test: `tests/test_cli_write.py`

**Interfaces:**
- Consumes: `Vault`, `read_passphrase` (Task 6), `Executor` (Task 9), `clipboard.copy` (Task 10), helpers from Task 11.
- Produces:
  - `sv set <secret> [--generate] [--preset P] [--length N]` — TTY-gated. Prompts passphrase (with confirm on first vault creation). Manual: `getpass` value twice. `--generate`: create value; if `settings.show_generated_secrets` is true → print value once with warning + attempt `clipboard.copy` (report which); else → confirm stored, no display. Updates vault + `state.set_value_hash`. Auto-registers unknown secret names in the registry.
  - `sv import <env-file> --project <name> [--host H] [--remote-path P] [--target-name N] [--scoped] [--map LOGICAL=ENVVAR ...]` — parses KEY=VALUE lines (values NOT read into output — only keys), registers secrets (prefixed `project/KEY` when `--scoped`) and an env-file target (default: `host=local`, `path=<the file>`, name `<project>-env`). Idempotent. Never prints values; exits 0 with summary of what was added.
  - `sv apply [--dry-run] [--secret S ...] [--target T ...] [--force] [--yes]` — TTY-gated (except `--dry-run`, which needs no vault): builds plan, prints via `_print_plan`, asks `Push? [y/N]` unless `--yes`, prompts passphrase, executes, `state.record_push` for each ok write/command step's stale/stdin secrets, prints per-step ✓/✗ + summary; exit 1 if any step failed.
- Import parsing: lines matching `^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=` capture the key; everything after `=` is ignored.

- [ ] **Step 1: Write failing tests**

`tests/test_cli_write.py`:

```python
import json

from secrets_vault.cli import main
from secrets_vault.registry import Registry, Secret, Target
from secrets_vault.settings import Settings, save_settings
from secrets_vault.state import StateStore
from secrets_vault.vault import Vault


def unlock_tty(monkeypatch, passphrase="pw", value="typed-value-123"):
    import sys
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    prompts = []

    def fake_getpass(prompt=""):
        prompts.append(prompt)
        if "assphrase" in prompt:
            return passphrase
        return value
    monkeypatch.setattr("getpass.getpass", fake_getpass)
    return prompts


def test_set_requires_tty(monkeypatch):
    import sys
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    assert main(["set", "API_KEY"]) == 1


def test_set_stores_value_and_state(monkeypatch, tmp_home):
    unlock_tty(monkeypatch)
    assert main(["set", "API_KEY"]) == 0
    from secrets_vault.settings import load_settings
    v = Vault(load_settings().resolved_vault_path())
    assert v.load("pw")["API_KEY"]["value"] == "typed-value-123"
    assert StateStore().has_value("API_KEY")
    assert "API_KEY" in Registry.load().secrets      # auto-registered


def test_set_generate_shows_once(monkeypatch, capsys):
    unlock_tty(monkeypatch)
    monkeypatch.setattr("secrets_vault.clipboard.copy", lambda t: True)
    assert main(["set", "TOKEN", "--generate", "--preset", "hex", "--length", "8"]) == 0
    out = capsys.readouterr().out
    assert "will not be shown again" in out.lower()
    v = Vault(__import__("secrets_vault.settings", fromlist=["load_settings"]).load_settings().resolved_vault_path())
    assert v.load("pw")["TOKEN"]["value"] in out


def test_set_generate_display_disabled(monkeypatch, capsys):
    save_settings(Settings(show_generated_secrets=False))
    unlock_tty(monkeypatch)
    assert main(["set", "TOKEN", "--generate"]) == 0
    out = capsys.readouterr().out
    v = Vault(__import__("secrets_vault.settings", fromlist=["load_settings"]).load_settings().resolved_vault_path())
    assert v.load("pw")["TOKEN"]["value"] not in out
    assert "display disabled" in out.lower()


def test_import_registers_keys_not_values(tmp_path, capsys):
    env = tmp_path / ".env"
    env.write_text("API_KEY=sk-live-secret\nexport DB_URL=postgres://x\n# comment\n")
    assert main(["import", str(env), "--project", "maestro", "--scoped"]) == 0
    reg = Registry.load()
    assert "maestro/API_KEY" in reg.secrets and "maestro/DB_URL" in reg.secrets
    t = reg.targets["maestro-env"]
    assert t.host == "local" and t.path == str(env)
    assert t.key_map == {"maestro/API_KEY": "API_KEY", "maestro/DB_URL": "DB_URL"}
    assert "sk-live-secret" not in capsys.readouterr().out
    # idempotent
    assert main(["import", str(env), "--project", "maestro", "--scoped"]) == 0


def test_apply_dry_run_no_tty_needed(monkeypatch, capsys, tmp_path):
    import sys
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    reg = Registry()
    reg.add_secret(Secret(name="A"))
    reg.add_target(Target(name="t1", type="env-file", host="local",
                          path=str(tmp_path / "x.env"), keys=["A"]))
    reg.save()
    StateStore().set_value_hash("A", "v")
    assert main(["apply", "--dry-run", "--yes"]) == 0
    assert "dry-run" in capsys.readouterr().out


def test_apply_executes_and_records(monkeypatch, tmp_path, capsys):
    unlock_tty(monkeypatch)
    reg = Registry()
    reg.add_secret(Secret(name="A"))
    out_file = tmp_path / "x.env"
    reg.add_target(Target(name="t1", type="env-file", host="local",
                          path=str(out_file), keys=["A"]))
    reg.save()
    # seed vault + state
    from secrets_vault.settings import load_settings
    Vault(load_settings().resolved_vault_path()).save(
        {"A": {"value": "the-value-9", "updated_at": "x"}}, "pw")
    StateStore().set_value_hash("A", "the-value-9")
    assert main(["apply", "--yes"]) == 0
    assert "A=the-value-9" in out_file.read_text()
    assert StateStore().is_stale("A", "t1") is False
```

- [ ] **Step 2: Run — expect FAIL (unknown subcommands).**

- [ ] **Step 3: Implement.** Add to `cli.py` (imports at top: `re`, `getpass`, `from pathlib import Path`, `from .executor import Executor`, `from .planner import build_plan` already present, `from .registry import Secret, Target`, `from .vault import TTYRequiredError, Vault, VaultError, read_passphrase`, `from . import clipboard`):

```python
_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=")


def _open_vault(settings, confirm_if_new=False):
    v = Vault(settings.resolved_vault_path())
    new = not v.exists()
    pw = read_passphrase(confirm=confirm_if_new and new)
    entries = v.load(pw) if not new else {}
    return v, pw, entries


def _cmd_set(args):
    from datetime import datetime, timezone
    settings, reg, st = _load_all()
    v, pw, entries = _open_vault(settings, confirm_if_new=True)
    if args.generate:
        value = generate(args.preset, args.length)
    else:
        value = getpass.getpass(f"Value for {args.secret}: ")
        if not value:
            print("empty value, aborted", file=sys.stderr)
            return 1
        if getpass.getpass("Confirm value: ") != value:
            print("values do not match", file=sys.stderr)
            return 1
    entries[args.secret] = {"value": value,
                            "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    v.save(entries, pw)
    st.set_value_hash(args.secret, value)
    if args.secret not in reg.secrets:
        reg.add_secret(Secret(name=args.secret))
        reg.save()
        print(f"note: registered new secret {args.secret!r}")
    if args.generate:
        if settings.show_generated_secrets:
            copied = clipboard.copy(value)
            print("WARNING: this value will not be shown again unless revealed in the TUI.")
            print(f"  {args.secret} = {value}")
            print("  (copied to clipboard)" if copied else "  (no clipboard backend available)")
        else:
            print(f"stored generated value for {args.secret} (display disabled app-wide)")
    else:
        print(f"stored {args.secret}")
    return 0


def _cmd_import(args):
    _, reg, _ = _load_all()
    src = Path(args.file).expanduser()
    if not src.exists():
        print(f"no such file: {src}", file=sys.stderr)
        return 2
    keys = []
    for line in src.read_text().splitlines():
        m = _ENV_LINE.match(line)
        if m:
            keys.append(m.group(1))
    if not keys:
        print("no KEY=VALUE lines found", file=sys.stderr)
        return 2
    explicit_map = dict(m.split("=", 1) for m in (args.map or []))
    key_map, added_secrets = {}, 0
    for key in keys:
        logical = f"{args.project}/{key}" if args.scoped else key
        for log_name, env_name in explicit_map.items():
            if env_name == key:
                logical = log_name
        if reg.add_secret(Secret(name=logical)):
            added_secrets += 1
        key_map[logical] = key
    tname = args.target_name or f"{args.project}-env"
    target = Target(name=tname, type="env-file", project=args.project,
                    host=args.host, path=args.remote_path or str(src),
                    key_map=key_map)
    changed = reg.add_target(target)
    reg.save()
    print(f"imported {len(keys)} keys from {src.name}: "
          f"{added_secrets} new secrets, target {tname!r} {'updated' if changed else 'unchanged'}")
    print("Run `sv tui` (or `sv set <name>`) to enter values, then `sv apply`.")
    return 0


def _cmd_apply(args):
    settings, reg, st = _load_all()
    errs = reg.validate()
    if errs:
        for e in errs:
            print(f"registry: {e}", file=sys.stderr)
        return 2
    plan = build_plan(reg, st, secrets=args.secret or None,
                      targets=args.target or None, force=args.force)
    _print_plan(plan, st)
    if plan.is_empty():
        return 0
    if args.dry_run:
        results = Executor(lambda s: "", ssh_options=settings.ssh_options).execute(plan, dry_run=True)
        for r in results:
            print(f"  ✓ [dry-run] {r.step.kind} {r.step.target}")
        return 0
    if not args.yes and input("Push? [y/N] ").strip().lower() != "y":
        print("aborted")
        return 1
    v, pw, entries = _open_vault(settings)
    values = {name: e["value"] for name, e in entries.items()}
    results = Executor(values.__getitem__, ssh_options=settings.ssh_options).execute(plan)
    failed = 0
    for r in results:
        mark = "✓" if r.ok else "✗"
        print(f"  {mark} {r.step.kind} {r.step.target} on {r.step.host}: {r.message}")
        if not r.ok:
            failed += 1
            continue
        if r.step.kind == "write-file":
            for logical in r.step.detail["env_keys"]:
                st.record_push(logical, r.step.target)
        elif r.step.kind == "command":
            st.record_push(r.step.detail["stdin_secret"], r.step.target)
    total = len(results)
    print(f"{total - failed}/{total} steps succeeded")
    return 1 if failed else 0
```

And in `build_parser()` add:

```python
    sp = sub.add_parser("set", help="set a secret value (interactive TTY only)")
    sp.add_argument("secret")
    sp.add_argument("--generate", action="store_true")
    sp.add_argument("--preset", choices=PRESETS, default=None)
    sp.add_argument("--length", type=int, default=None)
    sp.set_defaults(fn=_cmd_set)

    sp = sub.add_parser("import", help="register keys + target from an env file (no values read)")
    sp.add_argument("file")
    sp.add_argument("--project", required=True)
    sp.add_argument("--host", default="local")
    sp.add_argument("--remote-path", default="")
    sp.add_argument("--target-name", default="")
    sp.add_argument("--scoped", action="store_true",
                    help="register keys as project/KEY (app-scoped identities)")
    sp.add_argument("--map", action="append", metavar="LOGICAL=ENVVAR",
                    help="map an existing logical secret to an env var in this file")
    sp.set_defaults(fn=_cmd_import)

    sp = sub.add_parser("apply", help="push stale secrets (plan → confirm → apply)")
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--secret", action="append")
    sp.add_argument("--target", action="append")
    sp.add_argument("--force", action="store_true")
    sp.add_argument("--yes", action="store_true")
    sp.set_defaults(fn=_cmd_apply)
```

(`TTYRequiredError`/`VaultError` propagate to `main()`'s handler → redacted message, exit 1.)

- [ ] **Step 4: Run full suite — all tests pass.**

- [ ] **Step 5: Commit** — `"feat: sv set/import/apply with TTY-gated value operations"`

---

### Task 13: TUI — app skeleton (list, detail, staleness)

**Files:**
- Create: `src/secrets_vault/tui/__init__.py`, `src/secrets_vault/tui/app.py`
- Modify: `src/secrets_vault/cli.py` (add `sv tui` subcommand)
- Test: `tests/test_tui_app.py`

**Interfaces:**
- Produces: `SvApp(App)` in `tui/app.py` with attributes `registry: Registry`, `state: StateStore`, `settings: Settings`, `entries: dict | None` (None = locked), `passphrase: str | None`; method `refresh_table() -> None`; `selected_secret() -> str | None`. Bindings declared now, wired in Tasks 14–15: `n` new, `e` edit, `r` reveal, `g` generate, `p` push, `s` settings, `q` quit. CLI: `sv tui` runs `SvApp().run()`.

- [ ] **Step 1: Write failing test**

`tests/test_tui_app.py`:

```python
import pytest

from secrets_vault.registry import Registry, Secret, Target
from secrets_vault.state import StateStore
from secrets_vault.tui.app import SvApp


def seed():
    reg = Registry()
    reg.add_secret(Secret(name="API_KEY", description="shared"))
    reg.add_secret(Secret(name="OTHER"))
    reg.add_target(Target(name="t1", type="env-file", host="hermes",
                          path="/opt/x/.env", keys=["API_KEY"]))
    reg.save()
    st = StateStore()
    st.set_value_hash("API_KEY", "v1")


@pytest.mark.asyncio
async def test_table_lists_secrets_with_staleness():
    seed()
    app = SvApp()
    async with app.run_test() as pilot:
        table = app.query_one("#secrets-table")
        assert table.row_count == 2
        row = table.get_row_at(0)   # sorted: API_KEY first
        assert "API_KEY" in str(row[0])
        assert "stale" in str(row[2])       # 1 stale target
        assert "•" in str(row[1])           # has value


@pytest.mark.asyncio
async def test_detail_pane_masks_value():
    seed()
    app = SvApp()
    async with app.run_test() as pilot:
        detail = app.query_one("#detail")
        text = str(detail.render())
        assert "API_KEY" in text
        assert "••••" in text            # masked, never plaintext
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement**

`src/secrets_vault/tui/__init__.py` — empty file.

`src/secrets_vault/tui/app.py`:

```python
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


def run() -> None:
    SvApp().run()
```

In `cli.py` `build_parser()` add:

```python
    sp = sub.add_parser("tui", help="launch the TUI")
    sp.set_defaults(fn=lambda args: (__import__("secrets_vault.tui.app", fromlist=["run"]).run(), 0)[1])
```

- [ ] **Step 4: Run tests — expect 2 passed** (plus full suite still green).

- [ ] **Step 5: Commit** — `"feat: TUI skeleton with secrets table, detail pane, staleness badges"`

---

### Task 14: TUI — unlock, edit, reveal, generate modals

**Files:**
- Create: `src/secrets_vault/tui/modals.py`
- Modify: `src/secrets_vault/tui/app.py` (wire actions `new_secret`, `edit_secret`, `reveal`, `generate`)
- Test: `tests/test_tui_modals.py`

**Interfaces:**
- Consumes: `Vault`, `VaultError` (Task 6), `generate` (Task 3), `clipboard.copy` (Task 10), `SvApp` state fields (Task 13).
- Produces in `modals.py`:
  - `PassphraseModal(ModalScreen[str | None])` — masked `Input(password=True)`, confirm field shown when `create_mode=True`; dismisses with the passphrase or None.
  - `EditValueModal(ModalScreen[str | None])` — masked input for a named secret's value + confirm field; "Generate" button fills both fields from `generate(preset, length)` and remembers `generated=True`.
  - `GeneratedValueModal(ModalScreen[None])` — one-time display: warning text, the value, "Copy to clipboard" button (calls `clipboard.copy`, shows "copied" / "no clipboard backend"), Close.
- Produces on `SvApp`:
  - `async ensure_unlocked() -> bool` — pushes `PassphraseModal` (create mode if vault missing), loads/initializes `self.entries`, stores `self.passphrase`; notifies on `VaultError`; True when unlocked.
  - `save_vault() -> None` — writes `self.entries` via `Vault.save`, updates `state.set_value_hash` for changed names, `refresh_table()`.
  - `action_new_secret` / `action_edit_secret` — `EditValueModal`; on generated values: if `settings.show_generated_secrets` → push `GeneratedValueModal`, else `notify("stored (display disabled)")`. New secret names are `add_secret`'d to the registry and saved.
  - `action_reveal` — requires unlock; temporarily shows the value in the detail pane and reverts on next refresh.

- [ ] **Step 1: Write failing tests**

`tests/test_tui_modals.py`:

```python
import pytest

from secrets_vault.registry import Registry, Secret
from secrets_vault.settings import Settings, save_settings
from secrets_vault.state import StateStore
from secrets_vault.tui.app import SvApp
from secrets_vault.vault import Vault


def seed_vault(passphrase="pw"):
    from secrets_vault.settings import load_settings
    Registry().save()
    Vault(load_settings().resolved_vault_path()).save(
        {"API_KEY": {"value": "vaulted-value-1", "updated_at": "x"}}, passphrase)
    reg = Registry.load()
    reg.add_secret(Secret(name="API_KEY"))
    reg.save()
    StateStore().set_value_hash("API_KEY", "vaulted-value-1")


@pytest.mark.asyncio
async def test_unlock_flow():
    seed_vault()
    app = SvApp()
    async with app.run_test() as pilot:
        task = app.run_worker(app.ensure_unlocked())
        await pilot.pause()
        await pilot.click("#passphrase-input")
        await pilot.press(*"pw", "enter")
        await pilot.pause()
        assert app.entries is not None
        assert app.entries["API_KEY"]["value"] == "vaulted-value-1"


@pytest.mark.asyncio
async def test_wrong_passphrase_stays_locked():
    seed_vault()
    app = SvApp()
    async with app.run_test() as pilot:
        app.run_worker(app.ensure_unlocked())
        await pilot.pause()
        await pilot.click("#passphrase-input")
        await pilot.press(*"nope", "enter")
        await pilot.pause()
        assert app.entries is None


@pytest.mark.asyncio
async def test_generated_value_modal_one_time(monkeypatch):
    seed_vault()
    monkeypatch.setattr("secrets_vault.clipboard.copy", lambda t: True)
    app = SvApp()
    async with app.run_test() as pilot:
        app.entries = {"API_KEY": {"value": "vaulted-value-1", "updated_at": "x"}}
        app.passphrase = "pw"
        app.show_generated("NEW_TOKEN", "gen-value-abc123")
        await pilot.pause()
        text = str(app.screen.query_one("#generated-warning").render())
        assert "not be shown again" in text
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement**

`src/secrets_vault/tui/modals.py`:

```python
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, Static

from .. import clipboard
from ..generate import generate


class PassphraseModal(ModalScreen):
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


class EditValueModal(ModalScreen):
    """Returns (value, generated: bool) or None."""

    def __init__(self, secret_name: str, preset: str, length: int) -> None:
        super().__init__()
        self.secret_name = secret_name
        self.preset = preset
        self.length = length
        self.generated = False

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
            self.query_one("#value-input", Input).value = value
            self.query_one("#value-confirm", Input).value = value
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


class GeneratedValueModal(ModalScreen):
    def __init__(self, secret_name: str, value: str) -> None:
        super().__init__()
        self.secret_name = secret_name
        self.value = value

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Static(
                f"⚠ This value for [b]{self.secret_name}[/b] will not be shown again "
                "unless you reveal it manually.", id="generated-warning")
            yield Static(self.value, id="generated-value")
            yield Button("Copy to clipboard", id="copy")
            yield Button("Close", variant="primary", id="close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "copy":
            ok = clipboard.copy(self.value)
            self.app.notify("copied" if ok else "no clipboard backend available",
                            severity="information" if ok else "warning")
            return
        self.dismiss(None)
```

Additions to `tui/app.py` (imports: `from datetime import datetime, timezone`; `from ..vault import Vault, VaultError`; `from .modals import EditValueModal, GeneratedValueModal, PassphraseModal`):

```python
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
            from ..registry import Secret
            self.registry.add_secret(Secret(name=name))
            self.registry.save()
        self.refresh_table()
        if generated:
            if self.settings.show_generated_secrets:
                self.show_generated(name, value)
            else:
                self.notify(f"stored generated value for {name} (display disabled)")

    def show_generated(self, name: str, value: str) -> None:
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
        detail.update(f"[b]{name}[/b]\n\nvalue: {entry['value']}\n\n(press any arrow key to hide)")
```

And `NameModal` in `modals.py`:

```python
class NameModal(ModalScreen):
    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label("New secret name (use project/KEY for app-scoped):")
            yield Input(id="name-input")
            yield Button("OK", variant="primary", id="ok")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value or None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(self.query_one("#name-input", Input).value or None)
```

(Import `NameModal` in `app.py` alongside the other modals.)

- [ ] **Step 4: Run tests — expect 3 passed; full suite green.**

- [ ] **Step 5: Commit** — `"feat: TUI unlock/edit/reveal/generate with one-time display"`

---

### Task 15: TUI — plan/apply screen + settings screen

**Files:**
- Create: `src/secrets_vault/tui/plan_screen.py`
- Modify: `src/secrets_vault/tui/app.py` (wire `action_push`, `action_settings`)
- Test: `tests/test_tui_plan.py`

**Interfaces:**
- Consumes: `build_plan` (Task 8), `Executor` (Task 9), `SvApp.ensure_unlocked` (Task 14).
- Produces: `PlanScreen(ModalScreen)` — renders `Tree` of host → step descriptions (via the same wording as `_print_plan`), "Apply" and "Cancel" buttons; on Apply constructs `Executor(get_value, ssh_options)` from the app's unlocked entries, runs it in a thread worker, updates each tree node with ✓/✗ + redacted message, records pushes in `state` for ok steps (same rule as CLI apply: env_keys for write-file, stdin_secret for command), then shows "N/M succeeded"; Cancel/Close dismisses. `SettingsScreen(ModalScreen)` — toggles/edits `show_generated_secrets` (warning text + explicit confirm when turning off), `generate_preset`, `generate_length`; saves via `save_settings`.
- `action_push` requires unlock first (plan display itself doesn't, but apply does — unlock before showing keeps the flow one-shot).

- [ ] **Step 1: Write failing tests**

`tests/test_tui_plan.py`:

```python
import pytest

from secrets_vault.planner import build_plan
from secrets_vault.registry import Registry, Secret, Target
from secrets_vault.state import StateStore
from secrets_vault.tui.app import SvApp
from secrets_vault.tui.plan_screen import PlanScreen


def seed(tmp_path):
    reg = Registry()
    reg.add_secret(Secret(name="A"))
    reg.add_target(Target(name="t1", type="env-file", host="local",
                          path=str(tmp_path / "out.env"), keys=["A"]))
    reg.save()
    st = StateStore()
    st.set_value_hash("A", "value-nine-9")
    return reg, st


@pytest.mark.asyncio
async def test_plan_screen_lists_steps(tmp_path):
    reg, st = seed(tmp_path)
    app = SvApp()
    async with app.run_test() as pilot:
        app.entries = {"A": {"value": "value-nine-9", "updated_at": "x"}}
        app.passphrase = "pw"
        plan = build_plan(app.registry, app.state)
        app.push_screen(PlanScreen(plan))
        await pilot.pause()
        tree = app.screen.query_one("#plan-tree")
        labels = [str(node.label) for node in tree.root.children]
        assert any("local" in l for l in labels)


@pytest.mark.asyncio
async def test_apply_writes_and_records(tmp_path):
    reg, st = seed(tmp_path)
    app = SvApp()
    async with app.run_test() as pilot:
        app.entries = {"A": {"value": "value-nine-9", "updated_at": "x"}}
        app.passphrase = "pw"
        plan = build_plan(app.registry, app.state)
        app.push_screen(PlanScreen(plan))
        await pilot.pause()
        await pilot.click("#apply")
        await pilot.pause(0.5)
        assert "A=value-nine-9" in (tmp_path / "out.env").read_text()
        assert StateStore().is_stale("A", "t1") is False
```

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement**

`src/secrets_vault/tui/plan_screen.py`:

```python
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static, Tree

from ..executor import Executor


def step_label(step) -> str:
    if step.kind == "write-file":
        label = f"write {step.detail['path']} (stale: {', '.join(step.detail['stale'])})"
        if step.detail["missing"]:
            label += f" [no value yet: {', '.join(step.detail['missing'])}]"
        return label
    if step.kind == "command":
        return f"run {' '.join(step.detail['argv'])} <- {step.detail['stdin_secret']}"
    return f"exec {step.detail['cmd']}"


class PlanScreen(ModalScreen):
    def __init__(self, plan) -> None:
        super().__init__()
        self.plan = plan
        self._nodes = {}

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            tree: Tree = Tree("push plan", id="plan-tree")
            tree.root.expand()
            for host, steps in self.plan.by_host().items():
                host_node = tree.root.add(host, expand=True)
                for step in steps:
                    self._nodes[id(step)] = host_node.add_leaf(step_label(step))
            yield tree
            yield Static("", id="plan-summary")
            yield Button("Apply", variant="primary", id="apply",
                         disabled=self.plan.is_empty())
            yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        event.button.disabled = True
        self.run_worker(self._apply, thread=True)

    def _apply(self) -> None:
        app = self.app
        values = {name: e["value"] for name, e in app.entries.items()}
        ex = Executor(values.__getitem__, ssh_options=app.settings.ssh_options)
        results = ex.execute(self.plan)
        ok_count = 0
        for r in results:
            node = self._nodes[id(r.step)]
            mark = "✓" if r.ok else "✗"
            app.call_from_thread(node.set_label, f"{mark} {step_label(r.step)} — {r.message}")
            if r.ok:
                ok_count += 1
                if r.step.kind == "write-file":
                    for logical in r.step.detail["env_keys"]:
                        app.state.record_push(logical, r.step.target)
                elif r.step.kind == "command":
                    app.state.record_push(r.step.detail["stdin_secret"], r.step.target)
        app.call_from_thread(
            self.query_one("#plan-summary", Static).update,
            f"{ok_count}/{len(results)} steps succeeded")
        app.call_from_thread(app.refresh_table)
```

`SettingsScreen` (append to `modals.py`):

```python
from textual.widgets import Checkbox, Select

from ..generate import PRESETS
from ..settings import save_settings


class SettingsScreen(ModalScreen):
    def compose(self) -> ComposeResult:
        s = self.app.settings
        with Vertical(id="dialog"):
            yield Label("Settings")
            yield Checkbox("Show generated secrets once after creating them",
                           value=s.show_generated_secrets, id="show-gen")
            yield Label("Generation preset / length:")
            yield Select(((p, p) for p in PRESETS), value=s.generate_preset, id="preset")
            yield Input(value=str(s.generate_length), id="length")
            yield Static("", id="settings-warning")
            yield Button("Save", variant="primary", id="save")
            yield Button("Cancel", id="cancel")

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        warning = self.query_one("#settings-warning", Static)
        if not event.value:
            warning.update("⚠ Generated values will NEVER be displayed anywhere. "
                           "They will only be retrievable via manual reveal.")
        else:
            warning.update("")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        s = self.app.settings
        s.show_generated_secrets = self.query_one("#show-gen", Checkbox).value
        s.generate_preset = self.query_one("#preset", Select).value
        try:
            s.generate_length = max(1, int(self.query_one("#length", Input).value))
        except ValueError:
            pass
        save_settings(s)
        self.app.notify("settings saved")
        self.dismiss(None)
```

Wire in `app.py`:

```python
    def action_push(self) -> None:
        self.run_worker(self._push())

    async def _push(self) -> None:
        if not await self.ensure_unlocked():
            return
        from ..planner import build_plan
        from .plan_screen import PlanScreen
        plan = build_plan(self.registry, self.state)
        self.push_screen(PlanScreen(plan))

    def action_settings(self) -> None:
        from .modals import SettingsScreen
        self.push_screen(SettingsScreen())
```

- [ ] **Step 4: Run tests — expect 2 passed; full suite green.**

- [ ] **Step 5: Commit** — `"feat: TUI plan/apply screen with live results and settings screen"`

---

### Task 16: Integration test over real SSH (localhost)

**Files:**
- Create: `tests/test_integration_ssh.py`

**Interfaces:**
- Consumes: the full stack (registry → state → planner → executor).
- Skips cleanly (`pytest.mark.integration` + runtime skip) when `ssh -o BatchMode=yes localhost true` fails, so CI without SSH stays green.

- [ ] **Step 1: Write the test**

`tests/test_integration_ssh.py`:

```python
import subprocess

import pytest

from secrets_vault.executor import Executor
from secrets_vault.planner import build_plan
from secrets_vault.registry import Registry, Secret, Target
from secrets_vault.state import StateStore


def ssh_localhost_works() -> bool:
    return subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3", "localhost", "true"],
        capture_output=True).returncode == 0


pytestmark = pytest.mark.integration


@pytest.mark.skipif(not ssh_localhost_works(), reason="ssh localhost not available")
def test_full_push_over_ssh(tmp_path):
    remote_file = tmp_path / "pushed.env"
    reg = Registry()
    reg.add_secret(Secret(name="API_KEY"))
    reg.add_target(Target(name="it", type="env-file", host="localhost",
                          path=str(remote_file), keys=["API_KEY"],
                          restart=[f"test -f {remote_file}"]))
    st = StateStore()
    st.set_value_hash("API_KEY", "integration-value-1")

    plan = build_plan(reg, st)
    assert not plan.is_empty()
    results = Executor({"API_KEY": "integration-value-1"}.__getitem__).execute(plan)
    assert all(r.ok for r in results), [r.message for r in results]
    content = remote_file.read_text()
    assert "API_KEY=integration-value-1" in content
    mode = remote_file.stat().st_mode & 0o777
    assert mode == 0o600
```

- [ ] **Step 2: Run**

```bash
/mnt/d/Documents/Code/GitHub/secrets-vault/.venv_linux/bin/pytest /mnt/d/Documents/Code/GitHub/secrets-vault/tests/test_integration_ssh.py -v
```

Expected: 1 passed (or 1 skipped on machines without `ssh localhost`). Both outcomes are acceptable; do not fake a pass.

- [ ] **Step 3: Commit** — `"test: end-to-end push over real ssh to localhost"`

---

### Task 17: Claude Code import skill + example config

**Files:**
- Create: `skills/import-secrets/SKILL.md`, `examples/registry.example.toml`, `examples/settings.example.toml`

**Interfaces:**
- Consumes: the `sv import` CLI contract from Task 12 (flags: `--project`, `--host`, `--remote-path`, `--target-name`, `--scoped`, `--map LOGICAL=ENVVAR`) and `sv list --json` for dedup checks.

- [ ] **Step 1: Write the skill**

`skills/import-secrets/SKILL.md`:

```markdown
---
name: import-secrets
description: Scan the user's projects for secret locations (.env files, systemd EnvironmentFile, docker-compose env_file, CI secrets) and register them in the central secrets-vault registry. Never reads or echoes secret values. Use when the user wants secrets-vault configured for one project or all of them.
---

# Import secrets into secrets-vault

You are configuring the user's **central** secrets-vault registry. Central
means all projects at once: one logical secret entry per real-world secret,
no matter how many apps consume it.

## Hard rules

1. **NEVER read, print, or store secret VALUES.** You may read env files
   only to extract KEY names (`sv import` does this safely for you —
   prefer it). If you must open a file that contains values, extract key
   names only and never echo a line containing `=` plus a value.
2. Never run `sv set`, `sv apply` (without `--dry-run`), or anything that
   prompts for the vault passphrase. Those are the user's alone.
3. Registry edits must be idempotent — check `sv list --json` and
   `sv targets --json` before adding.

## Procedure

1. **Scope.** If the user gave a path, scan that project. Otherwise scan
   all projects: get roots from `sv config` settings (`project_roots`) or
   the user's known code directories; list each project directory.
2. **Discover locations** in each project: `.env*` files (skip
   `.env.example`), `EnvironmentFile=` lines in `*.service`/unit files,
   `env_file:` in docker-compose files, CI secret references
   (`secrets.FOO` in GitHub workflows).
3. **Resolve identity across projects** — the step that makes rotation
   work:
   - Same provider credential reused in several projects (e.g.
     `OPENAI_API_KEY`) → ONE logical secret; add each project's target,
     using `--map LOGICAL=ENVVAR` if the env var name differs.
   - Same env var NAME but per-app values (e.g. `DATABASE_URL`) →
     app-scoped secrets via `--scoped` (registers `project/KEY`).
   - Unsure? Ask the user with AskUserQuestion (one question per key
     group, batched sensibly).
4. **Propose hosts.** Use what you know of the user's machines
   (`~/.ssh/config` aliases, deployment layout) to fill `--host` and
   `--remote-path` for deployed targets; the local project `.env` target
   uses the default `--host local`. Ask when ambiguous.
5. **Register** with `sv import <file> --project <name> [flags]` per
   discovered file, and `sv targets --json` to verify.
6. **Report**: list registered secrets/targets (names only) and finish
   with: run `sv tui` to enter values, then push.
```

- [ ] **Step 2: Write examples**

`examples/registry.example.toml`:

```toml
# Example secrets-vault registry (lives at ~/.config/secrets-vault/registry.toml).
# Structure only — values live encrypted in vault.age.

[secrets.OPENAI_API_KEY]
description = "Shared OpenAI key used by several apps"
tags = ["ai"]

[secrets."myapp/DATABASE_URL"]
description = "myapp production Postgres DSN"

[targets.prod-myapp]
type = "env-file"
project = "myapp"
host = "prodbox"                 # ssh alias from ~/.ssh/config
path = "/opt/myapp/.env"
mode = "600"
owner = "myapp:myapp"
keys = ["OPENAI_API_KEY"]
restart = ["sudo systemctl restart myapp"]
[targets.prod-myapp.key_map]
"myapp/DATABASE_URL" = "DATABASE_URL"

[targets.worker]
type = "systemd"
project = "myapp"
host = "prodbox"
unit = "myapp-worker.service"
path = "/etc/myapp/worker.env"
keys = ["OPENAI_API_KEY"]

[targets.github-actions]
type = "command"
project = "myapp"
host = "local"
command = ["gh", "secret", "set", "OPENAI_API_KEY", "-R", "me/myapp"]
keys = ["OPENAI_API_KEY"]
```

`examples/settings.example.toml`:

```toml
# ~/.config/secrets-vault/settings.toml
vault_path = ""                    # empty = ~/.config/secrets-vault/vault.age
project_roots = ["/home/me/code"]  # where /import-secrets sweeps
generate_preset = "urlsafe"
generate_length = 32
show_generated_secrets = true
ssh_options = []
```

- [ ] **Step 3: Verify example parses** — quick check that the example registry loads and validates cleanly:

```bash
SECRETS_VAULT_HOME=$(mktemp -d) /mnt/d/Documents/Code/GitHub/secrets-vault/.venv_linux/bin/python -c "
from pathlib import Path
from secrets_vault.registry import Registry
r = Registry.load(Path('/mnt/d/Documents/Code/GitHub/secrets-vault/examples/registry.example.toml'))
errs = r.validate()
assert not errs, errs
print('example ok:', len(r.secrets), 'secrets,', len(r.targets), 'targets')
"
```

Expected: `example ok: 2 secrets, 3 targets`.

- [ ] **Step 4: Commit** — `"feat: import-secrets Claude skill and example configs"`

---

### Task 18: Docs, README, redaction audit

**Files:**
- Create: `README.md`, `Docs/UserGuide.md`, `Docs/Security.md`
- Test: `tests/test_redaction_audit.py`

**Interfaces:**
- Consumes: everything. The audit test is the executable form of spec §4 invariant 2.

- [ ] **Step 1: Write the redaction audit test**

`tests/test_redaction_audit.py`:

```python
"""Spec §4: no secret value may ever appear in agent-visible CLI output."""
import json

from secrets_vault.cli import main
from secrets_vault.registry import Registry, Secret, Target
from secrets_vault.state import StateStore
from secrets_vault.vault import Vault

VALUE = "super-sensitive-value-xyz-42"


def seed(tmp_path):
    reg = Registry()
    reg.add_secret(Secret(name="API_KEY", description="k"))
    reg.add_target(Target(name="t1", type="env-file", host="local",
                          path=str(tmp_path / "o.env"), keys=["API_KEY"]))
    reg.save()
    from secrets_vault.settings import load_settings
    Vault(load_settings().resolved_vault_path()).save(
        {"API_KEY": {"value": VALUE, "updated_at": "x"}}, "pw")
    StateStore().set_value_hash("API_KEY", VALUE)


def test_agent_surface_never_contains_values(tmp_path, capsys):
    seed(tmp_path)
    for argv in (["list"], ["list", "--json"], ["show", "API_KEY"],
                 ["show", "API_KEY", "--json"], ["targets", "--json"],
                 ["plan"], ["plan", "--json"], ["apply", "--dry-run", "--yes"]):
        main(argv)
        captured = capsys.readouterr()
        combined = captured.out + captured.err
        assert VALUE not in combined, f"value leaked via sv {' '.join(argv)}"
```

- [ ] **Step 2: Run — expect 1 passed** (if it fails, that's a real leak: fix the leak, not the test).

- [ ] **Step 3: Write README.md** — public-facing: what it is (the one-paragraph pitch + the compromised-key rotation story), install (`pipx install secrets-vault`, needs `ssh`; `age` optional), quickstart (`sv import`, `sv tui`, `sv apply`), the agent-safety model (TTY boundary, structure-vs-values table from the spec), the Claude Code skill install (copy `skills/import-secrets` into `~/.claude/skills/` or reference via plugin), and a security section linking `Docs/Security.md`. Write `Docs/UserGuide.md` (every subcommand with examples; TUI keybindings; settings reference; target types with registry.toml snippets from `examples/`) and `Docs/Security.md` (threat model: what the design protects against — agent exfiltration, shoulder-surfing, repo leaks, plaintext at rest — and what it does not: a compromised user account with a keylogger, a malicious remote host). These are prose files; follow the spec's §1–§4 content. No placeholders — write complete documents.

- [ ] **Step 4: Full suite + sanity run**

```bash
/mnt/d/Documents/Code/GitHub/secrets-vault/.venv_linux/bin/pytest /mnt/d/Documents/Code/GitHub/secrets-vault/tests -v
/mnt/d/Documents/Code/GitHub/secrets-vault/.venv_linux/bin/sv --help
/mnt/d/Documents/Code/GitHub/secrets-vault/.venv_linux/bin/sv generate --preset hex --length 16
```

Expected: all tests pass; help text lists every subcommand; generate prints 32 hex chars.

- [ ] **Step 5: Commit** — `"docs: README, user guide, security model + redaction audit test"`

---

## Post-plan checklist (for the executor)

- After Task 18, run the whole suite one final time and update `Docs/CodeMap.md` if the user asks for one.
- Do NOT push or create a GitHub repo unless Leland asks.
- Deviations from the spec discovered during implementation: stop and flag, don't improvise.
