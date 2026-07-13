from secrets_vault import paths
from secrets_vault.state import StateStore


def test_no_value_means_not_stale():
    st = StateStore()
    assert st.has_value("A") is False
    assert st.is_stale("A", "t1") is False


def test_set_then_stale_then_pushed():
    st = StateStore()
    st.set_value_hash("A", "hunter2hunter2")
    assert st.has_value("A")
    assert st.is_stale("A", "t1") is True          # never pushed
    st.record_push("A", "t1")
    assert st.is_stale("A", "t1") is False
    assert st.pushed_at("A", "t1")                 # timestamp recorded
    st.set_value_hash("A", "newvalue-123")         # rotate
    assert st.is_stale("A", "t1") is True


def test_hash_is_salted_and_not_the_value():
    st = StateStore()
    h = st.hash_value("hunter2hunter2")
    assert "hunter2" not in h and len(h) == 64
    text = paths.state_path().read_text()
    st.set_value_hash("A", "hunter2hunter2")
    assert "hunter2" not in paths.state_path().read_text()


def test_persistence_across_instances():
    StateStore().set_value_hash("A", "v1")
    st2 = StateStore()
    assert st2.has_value("A")
    assert st2.hash_value("v1") == st2.value_hash("A")  # same salt reloaded
