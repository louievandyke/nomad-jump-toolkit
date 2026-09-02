"""Regex-based detectors for sensitive data.

Each :class:`Detector` pairs a report ``name`` (also used in the ``--report``
summary) with a compiled ``pattern`` and a placeholder ``label``. The label is
what shows up in the sanitized output as ``<{label}_{n}>``.

Adding a new detector is intentionally simple: append a ``Detector`` to
``REGEX_DETECTORS`` (or, for anything needing classification logic such as IPs,
wire it into ``sanitizer.engine``). See the README section "How to add a new
pattern".
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Detector:
    """A named regex detector.

    Attributes:
        name: Stable key used in reports (e.g. ``"VAULT_TOKEN"``).
        pattern: Compiled regex. The full match (``group(0)``) is replaced,
            unless ``group`` is set.
        label: Placeholder label. Output looks like ``<{label}_{n}>``. Secret
            bearing detectors use a ``REDACTED_`` prefix; contextual ones
            (hosts, orgs) do not, to keep the narrative readable.
        group: Optional capture-group index. When set, only that group is
            replaced and the rest of the match is preserved (used to keep
            labels like ``token =`` intact while redacting the value).
    """

    name: str
    pattern: re.Pattern
    label: str
    group: int | None = None


# ---------------------------------------------------------------------------
# Certificates / private keys (whole-block redaction, must run first)
# ---------------------------------------------------------------------------
PRIVATE_KEY = Detector(
    name="PRIVATE_KEY",
    pattern=re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
    label="REDACTED_PRIVATE_KEY",
)
CERTIFICATE = Detector(
    name="CERTIFICATE",
    pattern=re.compile(
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        re.DOTALL,
    ),
    label="REDACTED_CERTIFICATE",
)

# ---------------------------------------------------------------------------
# Secrets and tokens
# ---------------------------------------------------------------------------
JWT = Detector(
    name="JWT",
    pattern=re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    label="REDACTED_JWT",
)
VAULT_TOKEN = Detector(
    name="VAULT_TOKEN",
    pattern=re.compile(r"\b(?:hvs|hvb|hvr|s)\.[A-Za-z0-9._-]{20,}\b"),
    label="REDACTED_VAULT_TOKEN",
)
GITHUB_TOKEN = Detector(
    name="GITHUB_TOKEN",
    pattern=re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b"),
    label="REDACTED_GITHUB_TOKEN",
)
SLACK_TOKEN = Detector(
    name="SLACK_TOKEN",
    pattern=re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    label="REDACTED_SLACK_TOKEN",
)
BEARER_TOKEN = Detector(
    name="BEARER_TOKEN",
    # Only the credential after "Bearer " is captured so the keyword survives.
    pattern=re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{20,})"),
    label="REDACTED_BEARER_TOKEN",
    group=1,
)

# ---------------------------------------------------------------------------
# Cloud credentials
# ---------------------------------------------------------------------------
AWS_ACCESS_KEY = Detector(
    name="AWS_ACCESS_KEY",
    pattern=re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    label="REDACTED_AWS_ACCESS_KEY",
)
# Labeled AWS secret key, e.g. AWS_SECRET_ACCESS_KEY=... — capture only the value.
AWS_SECRET_KEY = Detector(
    name="AWS_SECRET_KEY",
    pattern=re.compile(
        r"(?i)\baws_secret_access_key\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
    ),
    label="REDACTED_AWS_SECRET_KEY",
    group=1,
)

# ---------------------------------------------------------------------------
# Generic labeled assignments: password = ..., token: ..., client_secret=...
# Capture group 2 is the secret value; the key/quotes around it are preserved.
# ---------------------------------------------------------------------------
GENERIC_SECRET = Detector(
    name="GENERIC_SECRET",
    # Longer key names listed first so e.g. "secret_key" wins over "secret".
    # The value group excludes "<>" so existing placeholders are never
    # re-redacted by a later pass.
    pattern=re.compile(
        r"(?i)\b(client_secret|secret_key|secret_id|secretid|access_key|api[_-]?key"
        r"|password|passwd|secret|token)\b"
        r"(\s*[:=]\s*['\"]?)"
        r"([^\s'\"<>]{6,})"
    ),
    label="REDACTED_SECRET",
    group=3,
)

# ---------------------------------------------------------------------------
# HashiCorp Nomad / Consul
# ---------------------------------------------------------------------------
# Nomad/Consul ACL token supplied via env var or config, e.g.
# ``NOMAD_TOKEN=...``, ``CONSUL_HTTP_TOKEN: ...``. The keyword is preserved and
# only the value is redacted. GENERIC_SECRET's bare ``token`` key does NOT fire
# on these because the underscore in ``NOMAD_TOKEN`` suppresses the ``\btoken\b``
# word boundary, so a dedicated detector is needed.
CONSUL_NOMAD_TOKEN = Detector(
    name="CONSUL_NOMAD_TOKEN",
    pattern=re.compile(
        r"(?i)\b(?:NOMAD_TOKEN|CONSUL_HTTP_TOKEN|CONSUL_TOKEN)\b"
        r"(\s*[:=]\s*['\"]?)"
        r"([^\s'\"<>]{6,})"
    ),
    label="REDACTED_ACL_TOKEN",
    group=2,
)
# Serf gossip encryption key: the ``encrypt`` field in a Nomad/Consul agent
# config or the ``-encrypt`` CLI flag. The value is base64; the length guard
# leaves boolean settings like ``encrypt = true`` untouched.
GOSSIP_KEY = Detector(
    name="GOSSIP_KEY",
    pattern=re.compile(
        r"(?i)\bencrypt\b"
        r"(\s*[:=]\s*['\"]?)"
        r"([A-Za-z0-9+/]{16,}={0,2})"
    ),
    label="REDACTED_GOSSIP_KEY",
    group=2,
)
# Consul ACL token-block roles (``tokens { agent = "<uuid>" default = "<uuid>" }``).
# The role keywords are too generic to key on alone, so a UUID-shaped value is
# the required signal — this never fires on settings like
# ``default_policy = "deny"`` or ``dns = "1.1.1.1"``. ``secret_id``/``secretid``
# are intentionally omitted; GENERIC_SECRET already covers those.
CONSUL_ACL_TOKEN = Detector(
    name="CONSUL_ACL_TOKEN",
    pattern=re.compile(
        r"(?i)\b(?:agent_recovery|agent|default|replication|dns"
        r"|config_file_service_registration|management)\b"
        r"(\s*[:=]\s*['\"]?)"
        r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    ),
    label="REDACTED_ACL_TOKEN",
    group=2,
)

# Contextual Nomad/Consul resource IDs (alloc/node/eval/deployment). These are
# not secrets but are cluster-identifying; they redact to *readable*, correlated
# placeholders (no REDACTED_ prefix) so the same id stays traceable across lines.
# The value is a full UUID or Nomad's 8-char short form; the trailing lookahead
# rejects partial matches inside a longer hex run.
_RESOURCE_ID_VALUE = (
    r"([0-9a-f]{8}(?:-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})?)"
    r"(?![0-9a-f-])"
)


def _resource_id(name: str, keyword: str, label: str) -> Detector:
    """A ``<keyword>[ _-]id = <uuid|short>`` detector keeping the keyword."""
    return Detector(
        name=name,
        pattern=re.compile(
            r"(?i)\b" + keyword + r"[\s_-]?id\b"
            r"(\s*[:=]\s*['\"]?)" + _RESOURCE_ID_VALUE
        ),
        label=label,
        group=2,
    )


NOMAD_ALLOC_ID = _resource_id("NOMAD_ALLOC_ID", "alloc", "ALLOC_ID")
NOMAD_NODE_ID = _resource_id("NOMAD_NODE_ID", "node", "NODE_ID")
NOMAD_EVAL_ID = _resource_id("NOMAD_EVAL_ID", "eval(?:uation)?", "EVAL_ID")
NOMAD_DEPLOYMENT_ID = _resource_id(
    "NOMAD_DEPLOYMENT_ID", "deploy(?:ment)?", "DEPLOYMENT_ID"
)

# ---------------------------------------------------------------------------
# Identity and customer data
# ---------------------------------------------------------------------------
EMAIL = Detector(
    name="EMAIL",
    pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    label="REDACTED_EMAIL",
)
URL = Detector(
    name="URL",
    pattern=re.compile(r"\bhttps?://[^\s<>'\"]+", re.IGNORECASE),
    label="URL",
)
PHONE = Detector(
    name="PHONE",
    # Requires separators between digit groups so bare numeric/hex runs (UUID
    # tails, ids) are not misread as phone numbers.
    pattern=re.compile(
        r"(?<![\w.])(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)|\d{2,4})[\s.-]\d{3,4}[\s.-]\d{3,4}(?![\w.])"
    ),
    label="REDACTED_PHONE",
)
UUID = Detector(
    name="UUID",
    pattern=re.compile(
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        re.IGNORECASE,
    ),
    label="UUID",
)


# Order matters. More specific / greedier patterns run first so they win over
# broader ones (e.g. a private-key block before anything inside it; a URL
# before the hostname detector would grab the host out of it).
REGEX_DETECTORS: list[Detector] = [
    PRIVATE_KEY,
    CERTIFICATE,
    JWT,
    VAULT_TOKEN,
    GITHUB_TOKEN,
    SLACK_TOKEN,
    BEARER_TOKEN,
    AWS_ACCESS_KEY,
    AWS_SECRET_KEY,
    CONSUL_NOMAD_TOKEN,
    GOSSIP_KEY,
    CONSUL_ACL_TOKEN,
    GENERIC_SECRET,
    NOMAD_ALLOC_ID,
    NOMAD_NODE_ID,
    NOMAD_EVAL_ID,
    NOMAD_DEPLOYMENT_ID,
    EMAIL,
    URL,
    PHONE,
    UUID,
]

DETECTORS_BY_NAME: dict[str, Detector] = {d.name: d for d in REGEX_DETECTORS}
