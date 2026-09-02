"""Sanitization orchestration.

Applies the active regex detectors for a profile, then handles the cases that
need real logic rather than a single regex: IP/CIDR classification (private vs
public via :mod:`ipaddress`), hostname detection with an allowlist, and literal
customer/org name redaction.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .patterns import DETECTORS_BY_NAME, Detector
from .profiles import Profile, get_profile
from .replacer import Finding, StableReplacer

# Product, protocol, and service words we never want to treat as a hostname.
DEFAULT_ALLOWLIST = {
    "nomad", "consul", "vault", "terraform", "packer", "boundary", "waypoint",
    "docker", "kubernetes", "k8s", "aws", "gcp", "azure", "linux", "windows",
    "http", "https", "tcp", "udp", "grpc", "tls", "ssl", "ssh", "dns", "ntp",
    "github", "gitlab", "slack", "jira",
}

# Final labels that strongly imply a real hostname/domain.
_KNOWN_TLDS = {
    "com", "net", "org", "io", "co", "gov", "edu", "dev", "app", "cloud",
    "ai", "me", "info", "biz", "us", "uk", "ca", "de", "fr", "jp", "au",
}
# Any label matching these implies an internal/service hostname.
_INTERNAL_LABELS = {
    "internal", "local", "consul", "lan", "corp", "svc", "cluster", "intra",
    "prod", "dev", "stg", "stage", "staging", "test", "qa", "node",
}

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CIDR = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
_IPV6 = re.compile(r"\b(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}\b")
# Dotted hostname / FQDN. Final label must start with a letter to avoid eating
# trailing octets of version numbers like "1.2.3".
_FQDN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]\b",
    re.IGNORECASE,
)
# Dot-less host with at least two hyphens ending in a numeric id, e.g.
# "nomad-client-01" or "customer-prod-vault-01". The two-hyphen minimum keeps
# tokens like "utf-8" or "sha-256" out.
_HYPHEN_HOST = re.compile(r"\b[a-z][a-z0-9]*(?:-[a-z0-9]+)+-\d{1,4}\b", re.IGNORECASE)
# Cloud region identifiers (us-west-2, eu-central-1, ap-southeast-1, ...) look
# like hostnames but are generic, non-sensitive infra context worth preserving.
_CLOUD_REGION = re.compile(
    r"^(?:us|eu|ap|sa|ca|me|af|cn|il)-"
    r"(?:east|west|central|north|south|northeast|northwest|southeast|southwest)-?"
    r"\d$",
    re.IGNORECASE,
)


@dataclass
class SanitizeResult:
    text: str
    findings: list[Finding] = field(default_factory=list)
    profile: str = ""

    @property
    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.kind] = counts.get(f.kind, 0) + 1
        return counts


def _apply_regex(text: str, detector: Detector, replacer: StableReplacer) -> str:
    """Run one regex detector, replacing either the whole match or one group."""

    def sub(match: re.Match) -> str:
        if detector.group is None:
            value = match.group(0)
            return replacer.replace(detector.name, detector.label, value)
        # Replace only the captured group; keep the surrounding text intact.
        value = match.group(detector.group)
        placeholder = replacer.replace(detector.name, detector.label, value)
        start, end = match.span(detector.group)
        return match.group(0)[: start - match.start()] + placeholder + match.group(0)[end - match.start():]

    return detector.pattern.sub(sub, text)


def _classify_ip(value: str) -> tuple[str, str] | None:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if addr.is_global:
        return ("PUBLIC_IP", "PUBLIC_IP")
    return ("PRIVATE_IP", "PRIVATE_IP")


def _replace_ips(text: str, regex: re.Pattern, replacer: StableReplacer) -> str:
    def sub(match: re.Match) -> str:
        value = match.group(0)
        classified = _classify_ip(value)
        if classified is None:
            return value  # not a valid IP; leave it alone
        name, label = classified
        return replacer.replace(name, label, value)

    return regex.sub(sub, text)


def _replace_cidrs(text: str, replacer: StableReplacer) -> str:
    def sub(match: re.Match) -> str:
        value = match.group(0)
        net_part, prefix = value.split("/")
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return value
        if net.is_global:
            name = label = "PUBLIC_CIDR"
        else:
            name = label = "PRIVATE_CIDR"
        # Key by the full CIDR so identical ranges share a placeholder; preserve
        # the prefix length so topology stays readable.
        placeholder = replacer.replace(name, label, value)
        return f"{placeholder}/{prefix}"

    return _CIDR.sub(sub, text)


def _should_redact_host(host: str, allowlist: set[str]) -> bool:
    if host.lower() in allowlist:
        return False
    labels = host.lower().split(".")
    if len(labels) == 1:
        return False
    if labels[-1] in _KNOWN_TLDS:
        return True
    if any(label in _INTERNAL_LABELS for label in labels):
        return True
    return len(labels) >= 3


def _replace_hostnames(
    text: str, replacer: StableReplacer, allowlist: set[str]
) -> str:
    def fqdn_sub(match: re.Match) -> str:
        host = match.group(0)
        if not _should_redact_host(host, allowlist):
            return host
        return replacer.replace("HOSTNAME", "HOST", host)

    def hyphen_sub(match: re.Match) -> str:
        host = match.group(0)
        if host.lower() in allowlist or _CLOUD_REGION.match(host):
            return host
        return replacer.replace("HOSTNAME", "HOST", host)

    text = _FQDN.sub(fqdn_sub, text)
    text = _HYPHEN_HOST.sub(hyphen_sub, text)
    return text


def _replace_orgs(
    text: str, replacer: StableReplacer, customer_names: list[str]
) -> str:
    for name in customer_names:
        if not name.strip():
            continue
        pattern = re.compile(r"\b" + re.escape(name) + r"\b", re.IGNORECASE)
        text = pattern.sub(
            lambda m: replacer.replace("ORG", "ORG", name), text
        )
    return text


def sanitize_text(
    text: str,
    profile: str | Profile = "infra-safe",
    *,
    customer_names: list[str] | None = None,
    allowlist: set[str] | None = None,
    extra_detectors: list[Detector] | None = None,
) -> SanitizeResult:
    """Sanitize ``text`` according to ``profile``.

    Args:
        text: The raw input.
        profile: Profile name or :class:`Profile` instance.
        customer_names: Literal organization/customer names to redact as
            ``<ORG_n>``.
        allowlist: Extra terms to never treat as hostnames (merged with the
            built-in product/protocol allowlist).
        extra_detectors: Custom regex detectors (e.g. from a ``.sanitizer.yml``)
            applied in every profile after the built-in ones.

    Returns:
        A :class:`SanitizeResult` with the sanitized text and findings.
    """
    prof = profile if isinstance(profile, Profile) else get_profile(profile)
    replacer = StableReplacer()
    full_allowlist = set(DEFAULT_ALLOWLIST)
    if allowlist:
        full_allowlist |= {a.lower() for a in allowlist}

    # 1. Regex detectors (secrets, tokens, emails, URLs, ...) in declared order,
    #    then any user-supplied custom detectors.
    for det_name in prof.regex_detectors:
        detector = DETECTORS_BY_NAME[det_name]
        text = _apply_regex(text, detector, replacer)
    for detector in extra_detectors or []:
        text = _apply_regex(text, detector, replacer)

    # 2. CIDRs before bare IPs (so "/16" survives), then IPv4 and IPv6.
    if prof.redact_cidrs:
        text = _replace_cidrs(text, replacer)
    if prof.redact_ips:
        text = _replace_ips(text, _IPV4, replacer)
        text = _replace_ips(text, _IPV6, replacer)

    # 3. Hostnames (URLs already removed, so we won't grab hosts out of them).
    if prof.redact_hostnames:
        text = _replace_hostnames(text, replacer, full_allowlist)

    # 4. Customer/org literals last: a name embedded in an FQDN has already been
    #    removed by the hostname pass, so this only catches standalone mentions.
    if prof.redact_orgs and customer_names:
        # Longer names first so "Acme Corp" wins over a bare "Acme".
        ordered = sorted(customer_names, key=len, reverse=True)
        text = _replace_orgs(text, replacer, ordered)

    return SanitizeResult(text=text, findings=replacer.findings, profile=prof.name)
