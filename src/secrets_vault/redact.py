"""Central redaction: every secret value ever seen in-process gets registered
here, and all user-visible/logged text is filtered through redact()."""
import logging
import os
import traceback

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
        if record.exc_info and not record.exc_text:
            record.exc_text = REDACTOR.redact(
                "".join(traceback.format_exception(*record.exc_info)).rstrip())
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = REDACTOR.redact(record.exc_text)
        if record.stack_info:
            record.stack_info = REDACTOR.redact(record.stack_info)
        return True


def get_logger() -> logging.Logger:
    log = logging.getLogger("secrets_vault")
    log.propagate = False

    # Compute the intended log path
    intended_path = str((paths.logs_dir() / "sv.log").resolve())

    # Check if a handler with this path already exists
    handler_exists = False
    for handler in log.handlers:
        if isinstance(handler, logging.FileHandler):
            current_path = str(os.path.abspath(handler.baseFilename))
            if current_path == intended_path:
                handler_exists = True
                break

    # If no matching handler exists, remove all handlers and add a new one
    if not handler_exists:
        for handler in log.handlers[:]:  # Copy the list to avoid modifying while iterating
            handler.close()
            log.removeHandler(handler)

        handler = logging.FileHandler(paths.logs_dir() / "sv.log")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        handler.addFilter(_RedactingFilter())
        log.addHandler(handler)
        log.setLevel(logging.INFO)

    return log
