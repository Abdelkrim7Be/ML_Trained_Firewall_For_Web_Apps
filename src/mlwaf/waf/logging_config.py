"""Structured logging.

One JSON object per line, with the request id on every line that has one, so an
incident is a grep rather than an archaeology exercise.
"""

from __future__ import annotations

import json
import logging
import sys

RESERVED = frozenset(vars(logging.LogRecord("", 0, "", 0, "", (), None)).keys()) | {
    "message", "asctime", "taskName",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Anything passed through `extra=` lands here without being enumerated.
        payload.update({
            k: v for k, v in record.__dict__.items()
            if k not in RESERVED and not k.startswith("_")
        })
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    # uvicorn ships its own handlers; route them through ours so the output is
    # one format rather than two interleaved.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers[:] = []
        lg.propagate = True
