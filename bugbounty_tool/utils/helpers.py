"""Logging helpers and small utilities."""
from __future__ import annotations

import logging
import sys
from typing import Optional


_RESET = "\x1b[0m"
_COLORS = {
    "DEBUG": "\x1b[38;5;244m",
    "INFO": "\x1b[38;5;39m",
    "WARNING": "\x1b[38;5;214m",
    "ERROR": "\x1b[38;5;203m",
    "CRITICAL": "\x1b[38;5;197m",
}


class _ColorFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        color = _COLORS.get(record.levelname, "")
        message = super().format(record)
        if color and sys.stderr.isatty():
            return f"{color}{message}{_RESET}"
        return message


def get_logger(name: str = "bugbounty", verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        return logger
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_ColorFormatter("[%(asctime)s] %(levelname)s %(message)s", "%H:%M:%S"))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False
    return logger


def banner() -> str:
    return r"""
   ___           ___                  __         _    _ _
  | _ )_  _ __ / __|___ _  _ _ _  _  / _|___ ___| |__(_) |__ _
  | _ \ || / _` (__/ _ \ || | ' \| || > _|/ -_|_-< / /| | / _` |
  |___/\_,_\__, |\___\___/\_,_|_||_|\_\_| \___/__/_\_\|_|_\__,_|
           |___/
        bug-bounty-toolkit  -  authorized testing only
"""


def authorization_warning() -> str:
    return (
        "WARNING: This tool performs active security probing. By running it you "
        "confirm that you have EXPLICIT written authorization to test the "
        "target. Unauthorized testing is illegal in most jurisdictions."
    )


def truncate(value: Optional[str], length: int = 120) -> str:
    if not value:
        return ""
    value = " ".join(value.split())
    if len(value) <= length:
        return value
    return value[: length - 1] + "…"
