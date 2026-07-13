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
