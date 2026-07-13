"""Central redaction: every secret value ever seen in-process gets registered
here, and all user-visible/logged text is filtered through redact()."""
import logging

from . import paths

_MIN_LEN = 4


class Redactor:
    def __init__(self) -> None:
        self._values: set[str] = set()

    def add(self, value: str) -> None:
        if value and len(value) >= _MIN_LEN:
            self._values.add(value)

    def redact(self, text: str) -> str:
        for v in sorted(self._values, key=len, reverse=True):
            text = text.replace(v, "[REDACTED]")
        return text


REDACTOR = Redactor()


def redact(text: str) -> str:
    return REDACTOR.redact(text)


class _RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = REDACTOR.redact(record.getMessage())
        record.args = ()
        return True


def get_logger() -> logging.Logger:
    log = logging.getLogger("secrets_vault")
    if not log.handlers:
        handler = logging.FileHandler(paths.logs_dir() / "sv.log")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        handler.addFilter(_RedactingFilter())
        log.addHandler(handler)
        log.setLevel(logging.INFO)
    return log
