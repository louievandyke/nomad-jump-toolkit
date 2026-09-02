"""Local-first support-text sanitizer.

Public API:
    sanitize_text(text, profile="infra-safe", ...) -> SanitizeResult
"""

from .config import Config, ConfigError, find_config, load_config
from .engine import SanitizeResult, sanitize_text
from .profiles import DEFAULT_PROFILE, PROFILES, get_profile
from .replacer import Finding, StableReplacer

__version__ = "0.1.0"

__all__ = [
    "sanitize_text",
    "SanitizeResult",
    "Finding",
    "StableReplacer",
    "PROFILES",
    "DEFAULT_PROFILE",
    "get_profile",
    "Config",
    "ConfigError",
    "load_config",
    "find_config",
    "__version__",
]
