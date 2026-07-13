import secrets_vault.clipboard as cb


def test_pyperclip_path(monkeypatch):
    sent = {}
    monkeypatch.setattr(cb, "_pyperclip_copy", lambda t: sent.setdefault("v", t))
    assert cb.copy("hello") is True
    assert sent["v"] == "hello"


def test_wsl_fallback(monkeypatch):
    def boom(_):
        raise RuntimeError("no display")
    calls = {}
    monkeypatch.setattr(cb, "_pyperclip_copy", boom)
    monkeypatch.setattr(cb.shutil, "which", lambda n: "/mnt/c/Windows/System32/clip.exe")
    monkeypatch.setattr(cb.subprocess, "run",
                        lambda argv, **kw: calls.setdefault("argv", argv))
    assert cb.copy("hello") is True
    assert calls["argv"] == ["/mnt/c/Windows/System32/clip.exe"]


def test_no_backend(monkeypatch):
    def boom(_):
        raise RuntimeError
    monkeypatch.setattr(cb, "_pyperclip_copy", boom)
    monkeypatch.setattr(cb.shutil, "which", lambda n: None)
    assert cb.copy("hello") is False
