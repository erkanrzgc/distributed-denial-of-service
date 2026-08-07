import logging
import sys
from enum import Enum
from typing import Optional

import structlog
import orjson


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


def setup_logger(
    level: LogLevel = LogLevel.INFO,
    format_type: str = "console",
    log_file: Optional[str] = None,
) -> structlog.BoundLogger:
    processors: list = []

    if format_type == "json":
        processors.extend([
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(serializer=orjson.dumps),
        ])
    else:
        processors.extend([
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="%H:%M:%S", utc=False),
            structlog.dev.ConsoleRenderer(colors=True),
        ])

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, level.upper()))
        logging.getLogger().addHandler(file_handler)

    return structlog.get_logger()


logger = structlog.get_logger(__name__)


def get_logger(name: Optional[str] = None) -> structlog.BoundLogger:
    if name:
        return structlog.get_logger(name)
    return logger
