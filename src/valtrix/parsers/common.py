"""Shared pieces for the dependency-file parsers.

Project files are untrusted input: sizes are capped, nothing is executed, and
every value is type-checked before use.
"""

from __future__ import annotations

import codecs
import json
import re
import tomllib
from pathlib import Path
from typing import Any, Dict

MAX_LOCK_BYTES = 50_000_000
MAX_DEPENDENCIES = 50_000

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class ParseError(Exception):
    """A dependency file could not be read."""


def clean(value: Any, limit: int = 300) -> str:
    """A safe one-line string from untrusted data ('' if it is not a string)."""
    if not isinstance(value, str):
        return ""
    return _CONTROL_CHARS.sub("", value).strip()[:limit]


def read_text(path: Path, limit: int = MAX_LOCK_BYTES) -> str:
    try:
        if path.stat().st_size > limit:
            raise ParseError(f"{path}: file is larger than {limit} bytes")
        data = path.read_bytes()
    except OSError as exc:
        raise ParseError(f"{path}: {exc.strerror or exc}") from exc
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encoding = "utf-16"
    else:
        encoding = "utf-8-sig"
    try:
        return data.decode(encoding)
    except UnicodeDecodeError as exc:
        raise ParseError(f"{path}: not valid {encoding} text") from exc


def read_toml(path: Path) -> Dict[str, Any]:
    text = read_text(path)
    try:
        return tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError) as exc:
        raise ParseError(f"{path}: not valid TOML ({_short(exc)})") from exc


def read_json(path: Path) -> Dict[str, Any]:
    text = read_text(path)
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise ParseError(f"{path}: not valid JSON ({_short(exc)})") from exc
    if not isinstance(data, dict):
        raise ParseError(f"{path}: expected a JSON object at the top level")
    return data


def _short(exc: BaseException) -> str:
    return clean(str(exc), 120) or type(exc).__name__


def table(value: Any) -> Dict[str, Any]:
    """`value` if it is a dict with string keys, otherwise an empty dict."""
    if isinstance(value, dict):
        return {k: v for k, v in value.items() if isinstance(k, str)}
    return {}


def items(value: Any) -> list:
    return value if isinstance(value, list) else []
