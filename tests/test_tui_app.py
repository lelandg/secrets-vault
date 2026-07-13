import pytest

from secrets_vault.registry import Registry, Secret, Target
from secrets_vault.state import StateStore
from secrets_vault.tui.app import SvApp


def seed():
    reg = Registry()
    reg.add_secret(Secret(name="API_KEY", description="shared"))
    reg.add_secret(Secret(name="OTHER"))
    reg.add_target(Target(name="t1", type="env-file", host="hermes",
                          path="/opt/x/.env", keys=["API_KEY"]))
    reg.save()
    st = StateStore()
    st.set_value_hash("API_KEY", "v1")


@pytest.mark.asyncio
async def test_table_lists_secrets_with_staleness():
    seed()
    app = SvApp()
    async with app.run_test() as pilot:
        table = app.query_one("#secrets-table")
        assert table.row_count == 2
        row = table.get_row_at(0)   # sorted: API_KEY first
        assert "API_KEY" in str(row[0])
        assert "stale" in str(row[2])       # 1 stale target
        assert "•" in str(row[1])           # has value


@pytest.mark.asyncio
async def test_detail_pane_masks_value():
    seed()
    app = SvApp()
    async with app.run_test() as pilot:
        detail = app.query_one("#detail")
        text = str(detail.render())
        assert "API_KEY" in text
        assert "••••" in text            # masked, never plaintext
