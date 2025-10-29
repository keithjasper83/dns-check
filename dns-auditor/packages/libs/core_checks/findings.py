# packages/libs/core-checks/findings.py

# SPDX-FileCopyrightText: 2025 The dns-auditor Contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Set, Tuple


# -------------------------------
# Core Types
# -------------------------------

class Status(str, Enum):
OK = "ok"
WARN = "warn"
FAIL = "fail"
INFO = "info"
ERROR = "error" # internal error (e.g., timeout); should not affect scoring the same as FAIL


@dataclass(frozen=True)
class FindingSpec:
"""
Static catalog entry describing a possible finding.
- code: stable machine-readable identifier (UPPERCASE_WITH_UNDERSCORES)
- default_status: suggested status when emitted
- title: short human title
- message_tmpl: f-string style template; format with **kwargs at emission
- remediation: actionable guidance (one or two sentences)
- tags: categories used for filtering (e.g., {'SPF','EMAIL'})
- references: optional list of relevant docs / RFC sections (plain strings)
"""
code: str
default_status: Status
title: str
message_tmpl: str
remediation: str
tags: Set[str] = field(default_factory=set)
references: Tuple[str, ...] = field(default_factory=tuple)


# -------------------------------
# Helper API (use these in checks)
# -------------------------------

import logging

def render_message(spec: FindingSpec, **fmt: Any) -> str:
    """Render a human-friendly message from the template."""
    try:
        return spec.message_tmpl.format(**fmt)
    except (KeyError, ValueError) as exc:
        logging.warning(
            "Failed to format message for FindingSpec '%s': %s. Falling back to unformatted template.",
            getattr(spec, "code", "<unknown>"),
            exc,
        )
        return spec.message_tmpl

class InvalidFindingCodeError(Exception):
    """Raised when an invalid finding code is provided to make_finding."""

def make_finding(
    code: str,
    *,
    status_override: Optional[Status] = None,
    data: Optional[Mapping[str, Any]] = None,
    evidence: Optional[Mapping[str, Any]] = None,
    message_args: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Create a normalized finding dict ready for persistence / API return.
    - code must exist in REGISTRY
    - status may be overridden (e.g., based on thresholds)
    - data is machine-readable detail
    - evidence is raw material captured (e.g., TXT strings, cert PEM)
    Raises:
        InvalidFindingCodeError: if code is not present in REGISTRY.
    """
    if code not in REGISTRY:
        raise InvalidFindingCodeError(f"Finding code '{code}' not found in REGISTRY.")
    spec = REGISTRY[code]
    msg = render_message(spec, **(message_args or {}))
    return {
"code": spec.code,
"status": (status_override or spec.default_status).value,
"title": spec.title,
"message": msg,
"remediation": spec.remediation,
"tags": sorted(spec.tags),
"references": list(spec.references),
"data": dict(data or {}),
"evidence": dict(evidence or {}),
}

def list_codes(*, include_tags: Optional[Iterable[str]] = None, exclude_tags: Optional[Iterable[str]] = None) -> List[str]:
"""List known codes, with optional tag filtering."""
inc = set(map(str.upper, include_tags or []))
exc = set(map(str.upper, exclude_tags or []))
out: List[str] = []
for code, spec in REGISTRY.items():
tags = {t.upper() for t in spec.tags}
if inc and not (tags & inc):
continue
if exc and (tags & exc):
continue
out.append(code)
return sorted(out)

def validate_registry() -> List[str]:
"""
Validate catalog invariants.
Returns a list of problems (empty if OK).
"""
problems: List[str] = []
seen: Set[str] = set()
for code, spec in REGISTRY.items():
if code != spec.code:
problems.append(f"{code}: REGISTRY key != spec.code")
if code in seen:
problems.append(f"{code}: duplicate code")
seen.add(code)
if not code.isupper():
problems.append(f"{code}: code not uppercase")
if not spec.title.strip():
problems.append(f"{code}: empty title")
if not spec.message_tmpl.strip():
problems.append(f"{code}: empty message_tmpl")
if spec.default_status not in Status.__members__.values():
problems.append(f"{code}: invalid default_status")
return problems


# -------------------------------
# Catalog
# -------------------------------
T = set # alias for brevity

REGISTRY: Dict[str, FindingSpec] = {}

def _add(spec: FindingSpec) -> None:
REGISTRY[spec.code] = spec

# ---------- General ----------
_add(FindingSpec(
code="CHECK_SUCCEEDED",
default_status=Status.OK,
title="Check succeeded",
message_tmpl="Check completed without issues.",
remediation="No action required.",
tags=T({"GENERAL"}),
))

_add(FindingSpec(
code="CHECK_SKIPPED",
default_status=Status.INFO,
title="Check skipped",
message_tmpl="Check skipped: {reason}",
remediation="Enable or provide the required inputs to run this check.",
tags=T({"GENERAL"}),
))

_add(FindingSpec(
code="CHECK_INTERNAL_ERROR",
default_status=Status.ERROR,
title="Internal error during check",
message_tmpl="An internal error occurred: {error_class}: {error_message}",
remediation="Re-run later. If persistent, open an issue with logs and anonymized inputs.",
tags=T({"GENERAL"}),
))

_add(FindingSpec(
code="NETWORK_TIMEOUT",
default_status=Status.ERROR,
title="Network timeout",
message_tmpl="The request timed out after {timeout_ms} ms.",
remediation="Retry with higher timeout or check connectivity/firewall.",
tags=T({"GENERAL","NETWORK"}),
))

_add(FindingSpec(
code="RATE_LIMITED",
default_status=Status.INFO,
title="Rate-limited by remote service",
message_tmpl="Remote endpoint applied rate limiting.",
remediation="Back off and retry later; avoid excessive polling.",
tags=T({"GENERAL","NETWORK"}),
))

# ---------- DNS Records ----------
_add(FindingSpec(
code="A_PRESENT",
default_status=Status.OK,
title="A record(s) present",
message_tmpl="{count} A record(s) found.",
remediation="No action required.",
tags=T({"DNS","RECORDS"}),
))

_add(FindingSpec(
code="AAAA_PRESENT",
default_status=Status.OK,
title="AAAA record(s) present",
message_tmpl="{count} AAAA record(s) found.",
remediation="No action required.",
tags=T({"DNS","RECORDS","IPV6"}),
))

_add(FindingSpec(
code="A_MISSING",
default_status=Status.FAIL,
title="A record missing",
message_tmpl="No A record found.",
remediation="Add at least one A record pointing to the service IPv4 address.",
tags=T({"DNS","RECORDS"}),
))

_add(FindingSpec(
code="AAAA_MISSING",
default_status=Status.WARN,
title="AAAA record missing",
message_tmpl="No AAAA record found (IPv6 not enabled).",
remediation="Consider adding AAAA to support IPv6 connectivity.",
tags=T({"DNS","RECORDS","IPV6"}),
))

_add(FindingSpec(
code="CNAME_AT_ZONE_APEX",
default_status=Status.FAIL,
title="CNAME at zone apex",
message_tmpl="CNAME found at the zone apex, which is not allowed in standard DNS.",
remediation="Replace apex CNAME with A/AAAA records or use ALIAS/ANAME if supported by your DNS provider.",
tags=T({"DNS","RECORDS"}),
))

_add(FindingSpec(
code="MX_PRESENT",
default_status=Status.OK,
title="MX record(s) present",
message_tmpl="{count} MX record(s) found.",
remediation="No action required.",
tags=T({"DNS","EMAIL","RECORDS"}),
))

_add(FindingSpec(
code="MX_MISSING",
default_status=Status.FAIL,
title="MX record missing",
message_tmpl="No MX records found for domain.",
remediation="Publish MX records pointing to your mail exchangers.",
tags=T({"DNS","EMAIL","RECORDS"}),
))

_add(FindingSpec(
code="TXT_PRESENT",
default_status=Status.OK,
title="TXT record(s) present",
message_tmpl="{count} TXT record(s) found.",
remediation="No action required.",
tags=T({"DNS","RECORDS"}),
))

_add(FindingSpec(
code="CAA_MISSING",
default_status=Status.WARN,
title="CAA not set",
message_tmpl="No CAA record is set; any CA may issue certificates.",
remediation="Restrict issuance with CAA records (e.g., '0 issue \"letsencrypt.org\"').",
tags=T({"DNS","TLS","RECORDS"}),
))

_add(FindingSpec(
code="SRV_MALFORMED",
default_status=Status.FAIL,
title="SRV record malformed/inconsistent",
message_tmpl="SRV record(s) appear malformed or inconsistent.",
remediation="Ensure SRV records specify priority, weight, port, and target correctly.",
tags=T({"DNS","RECORDS"}),
))

# ---------- SPF ----------
_add(FindingSpec(
code="SPF_PRESENT",
default_status=Status.OK,
title="SPF present",
message_tmpl="SPF TXT record found.",
remediation="Keep SPF within 10 DNS lookups and avoid overly permissive mechanisms.",
tags=T({"SPF","EMAIL"}),
))

_add(FindingSpec(
code="SPF_MISSING",
default_status=Status.FAIL,
title="SPF missing",
message_tmpl="No SPF TXT record found.",
remediation="Publish an SPF TXT record (e.g., 'v=spf1 mx -all').",
tags=T({"SPF","EMAIL"}),
))

_add(FindingSpec(
code="SPF_SYNTAX_ERROR",
default_status=Status.FAIL,
title="SPF syntax error",
message_tmpl="SPF record could not be parsed: {detail}",
remediation="Fix syntax; ensure it starts with 'v=spf1' and uses valid mechanisms/modifiers.",
tags=T({"SPF","EMAIL"}),
))

_add(FindingSpec(
code="SPF_LOOKUP_COUNT_HIGH",
default_status=Status.WARN,
title="SPF DNS lookup count high",
message_tmpl="{count} DNS lookups (near/over limit 10).",
remediation="Flatten includes or remove unused mechanisms to reduce lookups.",
tags=T({"SPF","EMAIL"}),
))

_add(FindingSpec(
code="SPF_ALL_PERMISSIVE",
default_status=Status.WARN,
title="SPF permissive 'all'",
message_tmpl="SPF ends with a permissive qualifier ('{qualifier}all').",
remediation="Use '-all' in production; '?all' or '~all' can be used during rollout.",
tags=T({"SPF","EMAIL"}),
))

_add(FindingSpec(
code="SPF_MULTIPLE_RECORDS",
default_status=Status.FAIL,
title="Multiple SPF records",
message_tmpl="Multiple SPF TXT records found.",
remediation="Publish exactly one SPF TXT record; merge contents.",
tags=T({"SPF","EMAIL"}),
))

# ---------- DMARC ----------
_add(FindingSpec(
code="DMARC_PRESENT",
default_status=Status.OK,
title="DMARC present",
message_tmpl="DMARC record found with policy p={p}.",
remediation="Monitor aggregate (rua) reports and tighten policy over time.",
tags=T({"DMARC","EMAIL"}),
))

_add(FindingSpec(
code="DMARC_MISSING",
default_status=Status.FAIL,
title="DMARC missing",
message_tmpl="No _dmarc TXT record found.",
remediation="Publish a DMARC record (e.g., 'v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain').",
tags=T({"DMARC","EMAIL"}),
))

_add(FindingSpec(
code="DMARC_POLICY_NONE",
default_status=Status.WARN,
title="DMARC policy 'none'",
message_tmpl="DMARC policy is 'none' (monitoring only).",
remediation="Consider moving to 'quarantine' or 'reject' after monitoring.",
tags=T({"DMARC","EMAIL"}),
))

_add(FindingSpec(
code="DMARC_RUA_INVALID",
default_status=Status.WARN,
title="DMARC rua invalid",
message_tmpl="DMARC 'rua' tag is missing or invalid.",
remediation="Set a valid 'rua=mailto:...' destination to receive aggregate reports.",
tags=T({"DMARC","EMAIL"}),
))

_add(FindingSpec(
code="DMARC_ALIGNMENT_RELAXED",
default_status=Status.WARN,
title="DMARC relaxed alignment",
message_tmpl="DMARC alignment is relaxed (adkim={adkim}, aspf={aspf}).",
remediation="Use strict alignment ('s') to tighten DMARC where feasible.",
tags=T({"DMARC","EMAIL"}),
))

# ---------- DKIM ----------
_add(FindingSpec(
code="DKIM_SELECTOR_OK",
default_status=Status.OK,
title="DKIM selector ok",
message_tmpl="DKIM selector '{selector}' published (key size {bits} bits).",
remediation="Rotate keys periodically; prefer 2048-bit or higher.",
tags=T({"DKIM","EMAIL","TLS"}),
))

_add(FindingSpec(
code="DKIM_SELECTOR_MISSING",
default_status=Status.WARN,
title="DKIM selector missing",
message_tmpl="No DKIM key found for selector '{selector}'.",
remediation="Publish a TXT record at '{selector}._domainkey' with the public key (p=...).",
tags=T({"DKIM","EMAIL"}),
))

_add(FindingSpec(
code="DKIM_KEY_WEAK",
default_status=Status.WARN,
title="DKIM key weak",
message_tmpl="DKIM key size {bits} bits is considered weak.",
remediation="Regenerate DKIM with at least 2048-bit RSA (or modern algorithm).",
tags=T({"DKIM","EMAIL","TLS"}),
))

_add(FindingSpec(
code="DKIM_SYNTAX_ERROR",
default_status=Status.FAIL,
title="DKIM TXT syntax error",
message_tmpl="Unable to parse DKIM TXT for selector '{selector}': {detail}",
remediation="Ensure the TXT includes a valid 'v=DKIM1;' and 'p=' parameter, with proper semicolon separators.",
tags=T({"DKIM","EMAIL"}),
))

# ---------- DNSSEC ----------
_add(FindingSpec(
code="DNSSEC_AD_BIT_VALIDATED",
default_status=Status.OK,
title="DNSSEC validated by resolver",
message_tmpl="Resolver indicates AD=1 (validated).",
remediation="No action required.",
tags=T({"DNSSEC","DNS"}),
))

_add(FindingSpec(
code="DNSSEC_DS_PRESENT",
default_status=Status.INFO,
title="DS present at parent",
message_tmpl="DS record present at parent zone.",
remediation="Ensure child zone publishes matching DNSKEY and signs records.",
tags=T({"DNSSEC","DNS"}),
))

_add(FindingSpec(
code="DNSSEC_DS_NO_DNSKEY",
default_status=Status.FAIL,
title="DS without DNSKEY",
message_tmpl="Parent has DS, but child zone DNSKEY missing.",
remediation="Publish the correct DNSKEY in the child zone or remove stale DS at parent.",
tags=T({"DNSSEC","DNS"}),
))

_add(FindingSpec(
code="DNSSEC_SIG_EXPIRED",
default_status=Status.FAIL,
title="RRSIG expired",
message_tmpl="DNSSEC signatures appear expired as of {now_iso}.",
remediation="Re-sign the zone and ensure signer automation/cron is healthy.",
tags=T({"DNSSEC","DNS"}),
))

_add(FindingSpec(
code="DNSSEC_NOT_ENABLED",
default_status=Status.WARN,
title="DNSSEC not enabled",
message_tmpl="Zone does not appear to be DNSSEC-enabled.",
remediation="Consider enabling DNSSEC for integrity protection (DS at parent + signed zone).",
tags=T({"DNSSEC","DNS"}),
))

# ---------- Nameserver Health ----------
_add(FindingSpec(
code="NS_SET_INCONSISTENT",
default_status=Status.FAIL,
title="Authoritative NS set inconsistent",
message_tmpl="Different NS sets observed across authorities.",
remediation="Publish a consistent NS set at parent and child; ensure glue is correct.",
tags=T({"NS_HEALTH","DNS"}),
))

_add(FindingSpec(
code="NS_LAME",
default_status=Status.FAIL,
title="Lame delegation",
message_tmpl="At least one listed NS is not authoritative for the zone.",
remediation="Remove or fix lame nameserver; verify zone loading and recursion settings.",
tags=T({"NS_HEALTH","DNS"}),
))

_add(FindingSpec(
code="NS_RECURSION_ENABLED_ON_AUTH",
default_status=Status.WARN,
title="Recursion enabled on authoritative NS",
message_tmpl="Authoritative nameserver responds to recursive queries.",
remediation="Disable recursion on authoritative servers to reduce abuse risk.",
tags=T({"NS_HEALTH","DNS","SECURITY"}),
))

_add(FindingSpec(
code="NS_TCP_UNAVAILABLE",
default_status=Status.FAIL,
title="TCP not available",
message_tmpl="Nameserver did not respond over TCP.",
remediation="Allow TCP/53 to support large responses and DNSSEC.",
tags=T({"NS_HEALTH","DNS"}),
))

_add(FindingSpec(
code="NS_EDNS_ISSUES",
default_status=Status.WARN,
title="EDNS(0) issues",
message_tmpl="EDNS(0) support appears limited or broken.",
remediation="Update nameserver software or adjust EDNS settings.",
tags=T({"NS_HEALTH","DNS"}),
))

# ---------- SMTP ----------
_add(FindingSpec(
code="SMTP_BANNER_OK",
default_status=Status.OK,
title="SMTP banner ok",
message_tmpl="SMTP banner received from {host}:{port}.",
remediation="No action required.",
tags=T({"SMTP","EMAIL"}),
))

_add(FindingSpec(
code="SMTP_UNREACHABLE",
default_status=Status.FAIL,
title="SMTP unreachable",
message_tmpl="Could not connect to SMTP server {host}:{port}.",
remediation="Verify firewall, DNS, and server availability.",
tags=T({"SMTP","EMAIL","NETWORK"}),
))

_add(FindingSpec(
code="SMTP_STARTTLS_SUPPORTED",
default_status=Status.OK,
title="STARTTLS supported",
message_tmpl="Server supports STARTTLS.",
remediation="Ensure strong ciphers and valid certificate chain.",
tags=T({"SMTP","EMAIL","TLS"}),
))

_add(FindingSpec(
code="SMTP_STARTTLS_NOT_SUPPORTED",
default_status=Status.WARN,
title="STARTTLS not supported",
message_tmpl="Server does not advertise STARTTLS.",
remediation="Enable STARTTLS to protect in-transit email.",
tags=T({"SMTP","EMAIL","TLS"}),
))

_add(FindingSpec(
code="SMTP_TLS_CERT_EXPIRES_SOON",
default_status=Status.WARN,
title="SMTP TLS certificate expiring",
message_tmpl="Certificate expires in {days} day(s).",
remediation="Renew the certificate before expiry.",
tags=T({"SMTP","EMAIL","TLS"}),
))

_add(FindingSpec(
code="SMTP_TLS_CERT_INVALID",
default_status=Status.FAIL,
title="SMTP TLS certificate invalid",
message_tmpl="Certificate appears invalid (hostname or chain issue).",
remediation="Fix hostname mismatch and ensure full chain is served.",
tags=T({"SMTP","EMAIL","TLS","SECURITY"}),
))

# ---------- HTTP/HTTPS ----------
_add(FindingSpec(
code="HTTP_OK",
default_status=Status.OK,
title="HTTP reachable",
message_tmpl="HTTP GET {url} returned {status_code}.",
remediation="No action required.",
tags=T({"HTTP","WEB"}),
))

_add(FindingSpec(
code="HTTP_UNREACHABLE",
default_status=Status.FAIL,
title="HTTP unreachable",
message_tmpl="Could not reach {url}.",
remediation="Verify DNS, firewall, and upstream service.",
tags=T({"HTTP","WEB","NETWORK"}),
))

_add(FindingSpec(
code="HTTPS_TLS_CERT_EXPIRES_SOON",
default_status=Status.WARN,
title="HTTPS certificate expiring",
message_tmpl="TLS certificate for {hostname} expires in {days} day(s).",
remediation="Renew the certificate; automate renewal if possible.",
tags=T({"HTTP","WEB","TLS"}),
))

_add(FindingSpec(
code="HTTPS_TLS_CERT_INVALID",
default_status=Status.FAIL,
title="HTTPS certificate invalid",
message_tmpl="Certificate for {hostname} appears invalid (hostname or chain issue).",
remediation="Serve correct SANs and full chain; verify OCSP stapling if used.",
tags=T({"HTTP","WEB","TLS","SECURITY"}),
))

_add(FindingSpec(
code="HSTS_MISSING",
default_status=Status.WARN,
title="HSTS missing",
message_tmpl="HSTS header not present.",
remediation="Enable HSTS with a conservative max-age; consider preload after validation.",
tags=T({"HTTP","WEB","SECURITY"}),
))

_add(FindingSpec(
code="SECURITY_TXT_MISSING",
default_status=Status.INFO,
title="security.txt missing",
message_tmpl="/.well-known/security.txt not found.",
remediation="Publish a security.txt to document your vulnerability disclosure policy.",
tags=T({"HTTP","WEB","SECURITY"}),
))

# ---------- WHOIS ----------
_add(FindingSpec(
code="WHOIS_OK",
default_status=Status.OK,
title="WHOIS retrieved",
message_tmpl="WHOIS data retrieved: registrar={registrar}.",
remediation="No action required.",
tags=T({"WHOIS"}),
))

_add(FindingSpec(
code="WHOIS_UNAVAILABLE",
default_status=Status.ERROR,
title="WHOIS unavailable",
message_tmpl="WHOIS data could not be retrieved (timeout or rate-limit).",
remediation="Retry later; some registries throttle WHOIS access.",
tags=T({"WHOIS"}),
))

_add(FindingSpec(
code="DOMAIN_EXPIRES_SOON",
default_status=Status.WARN,
title="Domain expiring",
message_tmpl="Domain expires in {days} day(s).",
remediation="Renew the domain before expiry.",
tags=T({"WHOIS","SECURITY"}),
))

_add(FindingSpec(
code="DOMAIN_EXPIRED",
default_status=Status.FAIL,
title="Domain expired",
message_tmpl="Domain appears expired as of {now_iso}.",
remediation="Renew immediately with the registrar.",
tags=T({"WHOIS","SECURITY"}),
))


# -------------------------------
# End of catalog
# -------------------------------
# Sanity-check at import in dev: (optional)
if __name__ == "__main__":
probs = validate_registry()
if probs:
print("Catalog problems:")
for p in probs:
print("-", p)
else:
print(f"Catalog OK. {len(REGISTRY)} codes defined.")
print("Sample:", list_codes()[:10])
