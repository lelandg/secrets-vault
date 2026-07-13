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
