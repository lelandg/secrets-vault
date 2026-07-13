import logging

from secrets_vault import paths
from secrets_vault.redact import REDACTOR, Redactor, get_logger, redact


def test_registered_values_are_replaced():
    r = Redactor()
    r.add("s3cr3t-value-123")
    assert r.redact("error: s3cr3t-value-123 rejected") == "error: [REDACTED] rejected"


def test_longest_match_first():
    r = Redactor()
    r.add("abc")
    r.add("abcdef")
    assert r.redact("abcdef") == "[REDACTED]"


def test_short_values_not_registered():
    r = Redactor()
    r.add("ab")  # too short: would shred normal text
    assert r.redact("lab report") == "lab report"


def test_module_singleton():
    REDACTOR.add("tok-99887766")
    assert redact("tok-99887766") == "[REDACTED]"


def test_logger_redacts(tmp_home):
    REDACTOR.add("hunter2hunter2")
    log = get_logger()
    log.error("value was hunter2hunter2")
    logging.shutdown()
    text = (paths.logs_dir() / "sv.log").read_text()
    assert "hunter2hunter2" not in text
    assert "[REDACTED]" in text


def test_logger_follows_env_change(tmp_path, monkeypatch):
    from secrets_vault.redact import get_logger
    monkeypatch.setenv("SECRETS_VAULT_HOME", str(tmp_path / "one"))
    log1 = get_logger()
    first = log1.handlers[0].baseFilename
    monkeypatch.setenv("SECRETS_VAULT_HOME", str(tmp_path / "two"))
    log2 = get_logger()
    second = log2.handlers[0].baseFilename
    assert first != second
    assert str(tmp_path / "two") in second


def test_logger_redacts_exception_tracebacks(tmp_home):
    import logging as _logging
    from secrets_vault import paths
    from secrets_vault.redact import REDACTOR, get_logger
    REDACTOR.add("traceback-secret-99")
    log = get_logger()
    try:
        raise RuntimeError("boom traceback-secret-99")
    except RuntimeError:
        log.exception("command failed")
    for h in log.handlers:
        h.flush()
    text = (paths.logs_dir() / "sv.log").read_text()
    assert "traceback-secret-99" not in text
    assert "[REDACTED]" in text
