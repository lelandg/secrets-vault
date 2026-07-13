from secrets_vault.planner import build_plan
from secrets_vault.registry import Registry, Secret, Target
from secrets_vault.state import StateStore


def setup():
    reg = Registry()
    reg.add_secret(Secret(name="API_KEY"))
    reg.add_secret(Secret(name="maestro/DATABASE_URL"))
    reg.add_secret(Secret(name="EMPTY_ONE"))
    reg.add_target(Target(name="hermes-maestro", type="env-file", host="hermes",
                          project="maestro", path="/opt/maestro/.env",
                          keys=["API_KEY", "EMPTY_ONE"],
                          key_map={"maestro/DATABASE_URL": "DATABASE_URL"},
                          restart=["sudo systemctl restart maestro"]))
    reg.add_target(Target(name="worker", type="systemd", host="devbox",
                          unit="worker.service", path="/etc/worker/env",
                          keys=["API_KEY"]))
    reg.add_target(Target(name="gh", type="command", host="local",
                          command=["gh", "secret", "set", "API_KEY"],
                          keys=["API_KEY"]))
    st = StateStore()
    st.set_value_hash("API_KEY", "v1")
    st.set_value_hash("maestro/DATABASE_URL", "postgres://x")
    return reg, st


def test_all_stale_initially():
    reg, st = setup()
    plan = build_plan(reg, st)
    kinds = [(s.kind, s.target) for s in plan.steps]
    assert ("write-file", "hermes-maestro") in kinds
    assert ("restart", "hermes-maestro") in kinds
    assert ("write-file", "worker") in kinds
    assert ("command", "gh") in kinds
    wf = next(s for s in plan.steps if s.target == "hermes-maestro" and s.kind == "write-file")
    assert wf.detail["env_keys"] == {"API_KEY": "API_KEY", "maestro/DATABASE_URL": "DATABASE_URL"}
    assert wf.detail["missing"] == ["EMPTY_ONE"]
    sysd = [s for s in plan.steps if s.target == "worker" and s.kind == "restart"]
    assert sysd[0].detail["cmd"] == "systemctl restart worker.service"


def test_fresh_targets_skipped():
    reg, st = setup()
    for t in ("hermes-maestro", "worker", "gh"):
        st.record_push("API_KEY", t)
    st.record_push("maestro/DATABASE_URL", "hermes-maestro")
    assert build_plan(reg, st).is_empty()
    assert not build_plan(reg, st, force=True).is_empty()


def test_secret_filter():
    reg, st = setup()
    plan = build_plan(reg, st, secrets=["maestro/DATABASE_URL"])
    assert {s.target for s in plan.steps} == {"hermes-maestro"}


def test_target_filter_and_by_host():
    reg, st = setup()
    plan = build_plan(reg, st, targets=["worker"])
    assert set(plan.by_host()) == {"devbox"}


def test_restart_follows_write():
    reg, st = setup()
    steps = [s for s in build_plan(reg, st).steps if s.target == "hermes-maestro"]
    assert [s.kind for s in steps] == ["write-file", "restart"]
