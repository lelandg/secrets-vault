import pytest

from secrets_vault.redact import redact
from secrets_vault.vault import TTYRequiredError, Vault, VaultError, read_passphrase


def test_round_trip(tmp_path):
    v = Vault(tmp_path / "vault.age")
    assert not v.exists()
    entries = {"API_KEY": {"value": "sk-live-veryverysecret", "updated_at": "2026-07-13T00:00:00+00:00"}}
    v.save(entries, "pw")
    assert v.exists()
    assert v.load("pw") == entries


def test_wrong_passphrase(tmp_path):
    v = Vault(tmp_path / "vault.age")
    v.save({"A": {"value": "somevalue123", "updated_at": "x"}}, "right")
    with pytest.raises(VaultError):
        v.load("wrong")


def test_file_is_age_format_not_plaintext(tmp_path):
    v = Vault(tmp_path / "vault.age")
    v.save({"A": {"value": "plainlyvisible99", "updated_at": "x"}}, "pw")
    raw = (tmp_path / "vault.age").read_bytes()
    assert b"plainlyvisible99" not in raw
    assert raw.startswith(b"age-encryption.org/v1")


def test_load_registers_redaction(tmp_path):
    v = Vault(tmp_path / "vault.age")
    v.save({"A": {"value": "leakable-value-42", "updated_at": "x"}}, "pw")
    v.load("pw")
    assert redact("oops leakable-value-42") == "oops [REDACTED]"


def test_passphrase_requires_tty(monkeypatch):
    import sys
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    with pytest.raises(TTYRequiredError):
        read_passphrase()


def test_passphrase_confirm_mismatch(monkeypatch):
    import sys
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    answers = iter(["one-passphrase", "different"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    with pytest.raises(VaultError):
        read_passphrase(confirm=True)
