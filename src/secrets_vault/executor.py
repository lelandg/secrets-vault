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
