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
