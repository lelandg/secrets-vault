"""`sv` CLI. The read surface (list/show/targets/plan/config check) is
agent-safe: values are structurally absent. Value operations (set/apply)
live behind read_passphrase()'s TTY requirement — see Task 12."""
import argparse
import getpass
import json
import re
import subprocess
import sys
from pathlib import Path

from . import clipboard
from .executor import Executor
from .generate import PRESETS, generate
from .planner import build_plan
from .redact import get_logger
from .registry import Registry, Secret, Target
from .settings import Settings, load_settings, save_settings
from .state import StateStore
from .vault import TTYRequiredError, Vault, VaultError, read_passphrase


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

    sp = sub.add_parser("tui", help="launch the TUI")
    sp.set_defaults(fn=lambda args: (__import__("secrets_vault.tui.app", fromlist=["run"]).run(), 0)[1])
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
