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
