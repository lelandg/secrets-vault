import subprocess

import pytest

from secrets_vault.executor import Executor
from secrets_vault.planner import build_plan
from secrets_vault.registry import Registry, Secret, Target
from secrets_vault.state import StateStore


def ssh_localhost_works() -> bool:
    return subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=3", "localhost", "true"],
        capture_output=True).returncode == 0


pytestmark = pytest.mark.integration


@pytest.mark.skipif(not ssh_localhost_works(), reason="ssh localhost not available")
def test_full_push_over_ssh(tmp_path):
    remote_file = tmp_path / "pushed.env"
    reg = Registry()
    reg.add_secret(Secret(name="API_KEY"))
    reg.add_target(Target(name="it", type="env-file", host="localhost",
                          path=str(remote_file), keys=["API_KEY"],
                          restart=[f"test -f {remote_file}"]))
    st = StateStore()
    st.set_value_hash("API_KEY", "integration-value-1")

    plan = build_plan(reg, st)
    assert not plan.is_empty()
    results = Executor({"API_KEY": "integration-value-1"}.__getitem__).execute(plan)
    assert all(r.ok for r in results), [r.message for r in results]
    content = remote_file.read_text()
    assert "API_KEY=integration-value-1" in content
    mode = remote_file.stat().st_mode & 0o777
    assert mode == 0o600
