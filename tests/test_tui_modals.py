import pytest

from secrets_vault.registry import Registry, Secret
from secrets_vault.settings import Settings, save_settings
from secrets_vault.state import StateStore
from secrets_vault.tui.app import SvApp
from secrets_vault.vault import Vault


def seed_vault(passphrase="pw"):
    from secrets_vault.settings import load_settings
    Registry().save()
    Vault(load_settings().resolved_vault_path()).save(
        {"API_KEY": {"value": "vaulted-value-1", "updated_at": "x"}}, passphrase)
    reg = Registry.load()
    reg.add_secret(Secret(name="API_KEY"))
    reg.save()
    StateStore().set_value_hash("API_KEY", "vaulted-value-1")


@pytest.mark.asyncio
async def test_unlock_flow():
    seed_vault()
    app = SvApp()
    async with app.run_test() as pilot:
        task = app.run_worker(app.ensure_unlocked())
        await pilot.pause()
        await pilot.click("#passphrase-input")
        await pilot.press(*"pw", "enter")
        await pilot.pause()
        assert app.entries is not None
        assert app.entries["API_KEY"]["value"] == "vaulted-value-1"


@pytest.mark.asyncio
async def test_wrong_passphrase_stays_locked():
    seed_vault()
    app = SvApp()
    async with app.run_test() as pilot:
        app.run_worker(app.ensure_unlocked())
        await pilot.pause()
        await pilot.click("#passphrase-input")
        await pilot.press(*"nope", "enter")
        await pilot.pause()
        assert app.entries is None


@pytest.mark.asyncio
async def test_generated_value_modal_one_time(monkeypatch):
    seed_vault()
    monkeypatch.setattr("secrets_vault.clipboard.copy", lambda t: True)
    app = SvApp()
    async with app.run_test() as pilot:
        app.entries = {"API_KEY": {"value": "vaulted-value-1", "updated_at": "x"}}
        app.passphrase = "pw"
        app.show_generated("NEW_TOKEN", "gen-value-abc123")
        await pilot.pause()
        text = str(app.screen.query_one("#generated-warning").render())
        assert "not be shown again" in text
