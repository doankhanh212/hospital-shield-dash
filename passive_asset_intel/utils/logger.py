"""Structured JSON logging setup."""

import json
import logging
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        """Serialize a log record to a JSON string.

        Standard fields: ts, level, module, msg.
        Any extra attributes attached to the record are included as context fields.
        """
        payload: dict = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "module": record.name,
            "msg": record.getMessage(),
        }
        # Merge extra context passed via `extra={}` on the logging call.
        # logging.LogRecord stores extras directly on the object; we skip
        # the standard attributes to avoid noise.
        standard_attrs = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__)
        for key, value in record.__dict__.items():
            if key not in standard_attrs and key not in payload:
                payload[key] = value
        return json.dumps(payload, default=str)


def setup_logger(name: str, level: str = "INFO") -> logging.Logger:
    """Create and return a logger that emits structured JSON to stderr.

    Args:
        name: Logger name (usually __name__ of the calling module).
        level: Minimum log level as a string (DEBUG, INFO, WARNING, ERROR).

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # already configured

    logger.setLevel(getattr(logging, level, logging.INFO))
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)
    logger.propagate = False
    return logger
