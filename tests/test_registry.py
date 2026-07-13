from secrets_vault.registry import Registry, Secret, Target


def make_target(**kw):
    base = dict(name="t1", type="env-file", host="hermes", path="/opt/app/.env",
                keys=["API_KEY"])
    base.update(kw)
    return Target(**base)


def test_all_keys_merges_key_map():
    t = make_target(keys=["API_KEY"], key_map={"maestro/DATABASE_URL": "DATABASE_URL"})
    assert t.all_keys() == {"API_KEY": "API_KEY", "maestro/DATABASE_URL": "DATABASE_URL"}


def test_round_trip(tmp_path):
    reg = Registry()
    reg.add_secret(Secret(name="API_KEY", description="shared key", tags=["ai"]))
    reg.add_secret(Secret(name="maestro/DATABASE_URL"))
    reg.add_target(make_target(project="maestro",
                               key_map={"maestro/DATABASE_URL": "DATABASE_URL"},
                               restart=["sudo systemctl restart maestro"]))
    p = tmp_path / "registry.toml"
    reg.save(p)
    loaded = Registry.load(p)
    assert loaded.secrets["API_KEY"].tags == ["ai"]
    assert loaded.targets["t1"].restart == ["sudo systemctl restart maestro"]
    assert loaded.targets["t1"].all_keys()["maestro/DATABASE_URL"] == "DATABASE_URL"


def test_targets_for():
    reg = Registry()
    reg.add_secret(Secret(name="API_KEY"))
    reg.add_target(make_target())
    reg.add_target(make_target(name="t2", host="devbox", keys=[],
                               key_map={"API_KEY": "OPENAI_KEY"}))
    assert sorted(t.name for t in reg.targets_for("API_KEY")) == ["t1", "t2"]


def test_add_is_idempotent():
    reg = Registry()
    assert reg.add_secret(Secret(name="A")) is True
    assert reg.add_secret(Secret(name="A")) is False
    assert reg.add_target(make_target()) is True
    assert reg.add_target(make_target()) is False


def test_validate_catches_problems():
    reg = Registry()
    reg.add_target(make_target(type="bogus"))                      # bad type
    reg.add_target(make_target(name="t2", path=""))                # env-file needs path
    reg.add_target(Target(name="t3", type="command", host="local",
                          command=[], keys=["A", "B"]))            # no command, 2 keys
    reg.add_target(Target(name="t4", type="systemd", host="devbox",
                          path="/etc/w/env", keys=["MISSING"]))    # no unit; unknown secret
    errs = "\n".join(reg.validate())
    assert "t1: unknown type" in errs
    assert "t2: env-file target requires 'path'" in errs
    assert "t3: command target requires 'command'" in errs
    assert "t3: command target takes exactly one key" in errs
    assert "t4: systemd target requires 'unit'" in errs
    assert "t4: references unknown secret 'MISSING'" in errs


def test_validate_ok():
    reg = Registry()
    reg.add_secret(Secret(name="API_KEY"))
    reg.add_target(make_target())
    assert reg.validate() == []


def test_add_secret_merges_changed_metadata():
    reg = Registry()
    assert reg.add_secret(Secret(name="A")) is True
    assert reg.add_secret(Secret(name="A", description="updated")) is True
    assert reg.secrets["A"].description == "updated"
    assert reg.add_secret(Secret(name="A", description="updated")) is False
