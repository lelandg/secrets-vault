import stat

from secrets_vault import paths
from secrets_vault.settings import Settings, load_settings, save_settings


def test_config_dir_honors_env_and_is_private(tmp_home):
    d = paths.config_dir()
    assert d == tmp_home
    assert stat.S_IMODE(d.stat().st_mode) == 0o700


def test_defaults_when_no_file():
    s = load_settings()
    assert s.generate_preset == "urlsafe"
    assert s.generate_length == 32
    assert s.show_generated_secrets is True
    assert s.resolved_vault_path() == paths.config_dir() / "vault.age"


def test_round_trip(tmp_home):
    s = Settings(vault_path="/tmp/x.age", project_roots=["/mnt/d/Code"],
                 show_generated_secrets=False)
    save_settings(s)
    loaded = load_settings()
    assert loaded == s
    assert stat.S_IMODE(paths.settings_path().stat().st_mode) == 0o600
