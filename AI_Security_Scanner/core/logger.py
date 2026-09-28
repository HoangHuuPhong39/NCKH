# -*- coding: utf-8 -*-
"""
core/logger.py - Structured Logging and Observability for AI Security Scanner

Provides standardized log formats, file rotation, and JSON structured logging
for production observability and thesis experimental audits.
"""

import json
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


class JsonFormatter(logging.Formatter):
    """Formats log records as JSON lines for SIEM/Logstash/Observability pipelines."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj, ensure_ascii=False)


def get_logger(name: str = "ai_scanner") -> logging.Logger:
    """Configures and returns a singleton logger with file rotation and console output."""
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    # Load logging config
    project_root = Path(__file__).resolve().parent.parent
    log_dir = project_root / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "scanner.log"

    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, level_name, logging.INFO)
    logger.setLevel(log_level)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_fmt = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler.setFormatter(console_fmt)
    logger.addHandler(console_handler)

    # Rotating file handler (10MB per file, 5 backups)
    try:
        file_handler = RotatingFileHandler(
            str(log_file),
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(console_fmt)
        logger.addHandler(file_handler)
    except Exception as e:
        logger.warning("Could not initialize file logger: %s", e)

    return logger


# Global logger instance
logger = get_logger("ai_scanner")
