import pytest

from secrets_vault.planner import build_plan
from secrets_vault.registry import Registry, Secret, Target
from secrets_vault.state import StateStore
from secrets_vault.tui.app import SvApp
from secrets_vault.tui.plan_screen import PlanScreen


def seed(tmp_path):
    reg = Registry()
    reg.add_secret(Secret(name="A"))
    reg.add_target(Target(name="t1", type="env-file", host="local",
                          path=str(tmp_path / "out.env"), keys=["A"]))
    reg.save()
    st = StateStore()
    st.set_value_hash("A", "value-nine-9")
    return reg, st


@pytest.mark.asyncio
async def test_plan_screen_lists_steps(tmp_path):
    reg, st = seed(tmp_path)
    app = SvApp()
    async with app.run_test() as pilot:
        app.entries = {"A": {"value": "value-nine-9", "updated_at": "x"}}
        app.passphrase = "pw"
        plan = build_plan(app.registry, app.state)
        app.push_screen(PlanScreen(plan))
        await pilot.pause()
        tree = app.screen.query_one("#plan-tree")
        labels = [str(node.label) for node in tree.root.children]
        assert any("local" in l for l in labels)


@pytest.mark.asyncio
async def test_apply_writes_and_records(tmp_path):
    reg, st = seed(tmp_path)
    app = SvApp()
    async with app.run_test() as pilot:
        app.entries = {"A": {"value": "value-nine-9", "updated_at": "x"}}
        app.passphrase = "pw"
        plan = build_plan(app.registry, app.state)
        app.push_screen(PlanScreen(plan))
        await pilot.pause()
        await pilot.click("#apply")
        await pilot.pause(0.5)
        assert "A=value-nine-9" in (tmp_path / "out.env").read_text()
        assert StateStore().is_stale("A", "t1") is False
