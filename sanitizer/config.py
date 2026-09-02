"""Optional ``.sanitizer.yml`` config loader.

To stay dependency-free, this parses a small, documented *subset* of YAML rather
than pulling in PyYAML. The supported schema is flat:

    customer_names:
      - Acme Corp
      - Globex

    allowlist:
      - my-special-01

    extra_patterns:
      - name: INTERNAL_CASE_ID
        regex: "CASE-[0-9]+"
        label: CASE_ID            # optional; defaults to REDACTED_<NAME>

Supported syntax: top-level keys, ``- scalar`` lists, and ``- key: value``
mapping lists (for ``extra_patterns``). Comments (``#``) and single/double
quoted scalars are handled. Anything fancier than the above is not supported.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .patterns import Detector

CONFIG_FILENAMES = (".sanitizer.yml", ".sanitizer.yaml")


class ConfigError(Exception):
    """Raised when a config file is present but cannot be parsed/validated."""


@dataclass
class Config:
    customer_names: list[str] = field(default_factory=list)
    allowlist: list[str] = field(default_factory=list)
    extra_detectors: list[Detector] = field(default_factory=list)


def _scalar(value: str) -> str:
    """Normalize a scalar: unwrap quotes, else strip an inline ``#`` comment."""
    value = value.strip()
    if value and value[0] in "\"'":
        quote = value[0]
        end = value.find(quote, 1)
        if end != -1:
            return value[1:end]
    if " #" in value:
        value = value.split(" #", 1)[0].rstrip()
    return value


def parse_minimal_yaml(text: str) -> dict:
    """Parse the supported YAML subset into a dict. See module docstring."""
    result: dict = {}
    current_list: list | None = None
    current_item: dict | None = None

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        stripped = raw.strip()

        if indent == 0:
            current_item = None
            if stripped.endswith(":"):
                key = stripped[:-1].strip()
                current_list = []
                result[key] = current_list
            elif ":" in stripped:
                key, value = stripped.split(":", 1)
                result[key.strip()] = _scalar(value)
                current_list = None
            else:
                raise ConfigError(f"Cannot parse line: {raw!r}")
            continue

        # Indented line: either a list item or a field of a mapping list item.
        if current_list is None:
            raise ConfigError(f"Unexpected indented line: {raw!r}")

        if stripped.startswith("- "):
            value = stripped[2:].strip()
            is_quoted = bool(value) and value[0] in "\"'"
            if ":" in value and not is_quoted:
                # "- key: value" begins a mapping list item.
                current_item = {}
                key, val = value.split(":", 1)
                current_item[key.strip()] = _scalar(val)
                current_list.append(current_item)
            else:
                current_list.append(_scalar(value))
                current_item = None
        elif current_item is not None and ":" in stripped:
            key, val = stripped.split(":", 1)
            current_item[key.strip()] = _scalar(val)
        else:
            raise ConfigError(f"Cannot parse line: {raw!r}")

    return result


def _build_detector(item: dict) -> Detector:
    if not isinstance(item, dict):
        raise ConfigError(f"extra_patterns entries must be mappings, got: {item!r}")
    name = item.get("name")
    regex = item.get("regex")
    if not name or not regex:
        raise ConfigError(
            f"extra_patterns entry needs both 'name' and 'regex': {item!r}"
        )
    try:
        pattern = re.compile(regex)
    except re.error as exc:
        raise ConfigError(f"Invalid regex for {name!r}: {exc}")
    label = item.get("label") or f"REDACTED_{name}"
    return Detector(name=name, pattern=pattern, label=label)


def config_from_dict(data: dict) -> Config:
    cfg = Config()
    for key in data:
        if key not in {"customer_names", "allowlist", "extra_patterns"}:
            raise ConfigError(f"Unknown config key: {key!r}")

    names = data.get("customer_names", []) or []
    allow = data.get("allowlist", []) or []
    if not isinstance(names, list) or not isinstance(allow, list):
        raise ConfigError("'customer_names' and 'allowlist' must be lists")
    cfg.customer_names = [str(n) for n in names]
    cfg.allowlist = [str(a) for a in allow]

    for item in data.get("extra_patterns", []) or []:
        cfg.extra_detectors.append(_build_detector(item))
    return cfg


def load_config(path: str | Path) -> Config:
    """Load and validate a config file. Raises :class:`ConfigError` on problems."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Cannot read config {str(path)!r}: {exc}")
    return config_from_dict(parse_minimal_yaml(text))


def find_config(start: str | Path | None = None) -> Path | None:
    """Find a config file in ``start`` (or the cwd), then its parent directories."""
    directory = Path(start) if start else Path.cwd()
    if directory.is_file():
        directory = directory.parent
    for parent in [directory, *directory.parents]:
        for name in CONFIG_FILENAMES:
            candidate = parent / name
            if candidate.is_file():
                return candidate
    return None
