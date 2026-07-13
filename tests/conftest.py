import pytest


@pytest.fixture(autouse=True)
def tmp_home(tmp_path, monkeypatch):
    """Point all config at a throwaway dir so tests never touch real config."""
    home = tmp_path / "svhome"
    monkeypatch.setenv("SECRETS_VAULT_HOME", str(home))
    return home
