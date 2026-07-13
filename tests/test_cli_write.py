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
