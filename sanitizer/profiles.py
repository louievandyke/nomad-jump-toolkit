"""Redaction profiles.

A profile decides which detectors are active and how network/host/org context
is handled. Ports, timestamps, protocols, status codes, version numbers, and
error messages are never matched by any detector, so they are preserved in
every profile.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Secret-bearing detectors that should fire in every profile.
_CORE_SECRETS = [
    "PRIVATE_KEY",
    "CERTIFICATE",
    "JWT",
    "VAULT_TOKEN",
    "GITHUB_TOKEN",
    "SLACK_TOKEN",
    "BEARER_TOKEN",
    "AWS_ACCESS_KEY",
    "AWS_SECRET_KEY",
    "CONSUL_NOMAD_TOKEN",
    "GOSSIP_KEY",
    "CONSUL_ACL_TOKEN",
    "GENERIC_SECRET",
    "EMAIL",
]

# Contextual Nomad/Consul resource IDs. Not secrets, but cluster-identifying;
# redacted to readable, correlated placeholders. Must run before UUID so a
# labeled alloc/node/eval/deployment id keeps its type instead of becoming a
# generic <UUID_n>.
_NOMAD_CONSUL_IDS = [
    "NOMAD_ALLOC_ID",
    "NOMAD_NODE_ID",
    "NOMAD_EVAL_ID",
    "NOMAD_DEPLOYMENT_ID",
]


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    regex_detectors: list[str]
    redact_ips: bool = True
    redact_cidrs: bool = True
    redact_hostnames: bool = True
    redact_orgs: bool = True


PROFILES: dict[str, Profile] = {
    "strict": Profile(
        name="strict",
        description=(
            "Aggressive. Redacts secrets, identity, network, URLs, UUIDs, and "
            "phone numbers. Use when unsure whether the content is safe."
        ),
        regex_detectors=[*_CORE_SECRETS, *_NOMAD_CONSUL_IDS, "URL", "UUID", "PHONE"],
    ),
    "infra-safe": Profile(
        name="infra-safe",
        description=(
            "Keeps infrastructure context useful. Redacts secrets, emails, "
            "URLs, customer names, hostnames, and IPs (via stable placeholders) "
            "while preserving ports, protocols, status codes, and error text."
        ),
        regex_detectors=[*_CORE_SECRETS, *_NOMAD_CONSUL_IDS, "URL"],
    ),
    "case-summary": Profile(
        name="case-summary",
        description=(
            "Optimized for pasting into an AI assistant. Removes customer "
            "identity and obvious secrets while keeping product names, "
            "versions, ports, and the technical narrative readable."
        ),
        regex_detectors=[*_CORE_SECRETS, *_NOMAD_CONSUL_IDS, "URL", "PHONE"],
    ),
}

DEFAULT_PROFILE = "infra-safe"


def get_profile(name: str) -> Profile:
    try:
        return PROFILES[name]
    except KeyError:
        valid = ", ".join(sorted(PROFILES))
        raise ValueError(f"Unknown profile '{name}'. Choose one of: {valid}")
