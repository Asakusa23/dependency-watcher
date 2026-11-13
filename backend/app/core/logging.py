from __future__ import annotations

import logging
import re
from typing import Any


SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|token|authorization|secret|password|bearer)\s*[=:]\s*[^\s,;]+"
)


class SecretRedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        if SECRET_PATTERN.search(message):
            record.msg = SECRET_PATTERN.sub(r"\1=<redacted>", message)
            record.args = ()
        return True


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.addFilter(SecretRedactionFilter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level.upper())
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in data.items():
        if re.search(r"(?i)(key|token|secret|password|authorization)", key):
            redacted[key] = "<redacted>" if value else ""
        elif isinstance(value, dict):
            redacted[key] = redact_mapping(value)
        else:
            redacted[key] = value
    return redacted
