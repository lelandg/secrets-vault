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
