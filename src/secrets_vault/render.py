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
