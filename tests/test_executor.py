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
    from secrets_vault.redact import REDACTOR
    REDACTOR.add(VALUES["API_KEY"])
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


def test_local_write_honors_owner_current_user(tmp_path):
    """Local write branch must chown when owner is set — matches the remote
    branch's chown behavior. Uses the current user so it succeeds without
    root privilege."""
    import getpass
    user = getpass.getuser()
    p = tmp_path / "app.env"
    ex = Executor(VALUES.__getitem__, runner=FakeRunner())
    step = wf_step(host="local", path=str(p))
    step.detail["owner"] = user
    results = ex.execute(Plan([step]))
    assert results[0].ok, results[0].message
    assert "API_KEY=sk-live-secret-xyz" in p.read_text()


def test_local_write_owner_unset_still_works(tmp_path):
    """No regression: owner unset (empty string) means no chown attempted."""
    p = tmp_path / "app.env"
    ex = Executor(VALUES.__getitem__, runner=FakeRunner())
    results = ex.execute(Plan([wf_step(host="local", path=str(p))]))
    assert results[0].ok, results[0].message
    assert "API_KEY=sk-live-secret-xyz" in p.read_text()


def test_local_write_bogus_owner_fails_with_chown_message(tmp_path):
    """A nonexistent owner should surface a clear ok=False chown-failed
    message rather than silently succeeding or crashing."""
    p = tmp_path / "app.env"
    ex = Executor(VALUES.__getitem__, runner=FakeRunner())
    step = wf_step(host="local", path=str(p))
    step.detail["owner"] = "sv-nonexistent-user-xyz:sv-nonexistent-group-xyz"
    results = ex.execute(Plan([step]))
    assert results[0].ok is False
    assert "chown failed" in results[0].message
    # file was still written before the chown attempt
    assert p.exists()


def test_local_write_sets_mode_at_creation_without_chmod(tmp_path, monkeypatch):
    """The final mode must come from os.open's mode arg, not a later chmod —
    a separate chmod step would reintroduce a world-readable window."""
    import os as _os
    import pathlib

    def _no_chmod(*args, **kwargs):
        raise AssertionError("chmod must not be called on the local write path")

    monkeypatch.setattr(_os, "chmod", _no_chmod)
    monkeypatch.setattr(pathlib.Path, "chmod", _no_chmod)
    old = _os.umask(0o000)
    try:
        p = tmp_path / "app.env"
        ex = Executor(VALUES.__getitem__, runner=FakeRunner())
        results = ex.execute(Plan([wf_step(host="local", path=str(p))]))
        assert results[0].ok
        assert (p.stat().st_mode & 0o777) == 0o600
    finally:
        _os.umask(old)
