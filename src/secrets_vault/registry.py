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
