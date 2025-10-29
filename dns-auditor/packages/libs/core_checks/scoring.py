# packages/libs/core-checks/scoring.py
#
# SPDX-FileCopyrightText: 2025 The dns-auditor Contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple

# -------------------------------
# Configuration
# -------------------------------

# Areas (logical buckets) and their weights toward the 100-point total.
AREA_WEIGHTS: Dict[str, int] = {
"DNS": 25,
"SPF": 15,
"DMARC": 20,
"DKIM": 10,
"DNSSEC": 15,
"NS_HEALTH": 10,
"SMTP": 3,
"HTTP": 2,
# WHOIS informs guidance but doesn't hurt score by default; set >0 if you want to penalize.
"WHOIS": 0,
}

# Per-status base penalties. These are multiplied by per-area multipliers below.
STATUS_BASE_PENALTY: Dict[str, float] = {
"ok": 0.0,
"info": 0.0,
"warn": 1.0,
# "error" is usually an internal/network issue — penalize lightly so we don't punish users for timeouts.
"error": 0.5,
"fail": 3.0,
}

# Optional per-area penalty multipliers (defaults to 1.0).
AREA_PENALTY_MULTIPLIER: Dict[str, float] = {
# Email posture is often critical:
"SPF": 1.2,
"DMARC": 1.4,
"DKIM": 1.1,
# DNSSEC/NS are important, but we keep room for adoption variance:
"DNSSEC": 1.0,
"NS_HEALTH": 1.1,
# DNS records baseline:
"DNS": 1.0,
# Service probes:
"SMTP": 0.9,
"HTTP": 0.6,
"WHOIS": 0.0, # informational by default
}

# Hard caps: an area can never lose more than its weight.
AREA_MAX_DEDUCTION: Dict[str, float] = {}

# Map finding tags to areas (first match wins). Tags compared case-insensitively.
TAG_TO_AREA_ORDERED: List[Tuple[str, str]] = [
("DMARC", "DMARC"),
("SPF", "SPF"),
("DKIM", "DKIM"),
("DNSSEC", "DNSSEC"),
("NS_HEALTH", "NS_HEALTH"),
("TLS", "HTTP"), # TLS-only web issues -> HTTP area (or SMTP based on context; see below)
("HTTP", "HTTP"),
("WEB", "HTTP"),
("SMTP", "SMTP"),
("EMAIL", None), # EMAIL + DMARC/SPF/DKIM tags will already have matched above.
("DNS", "DNS"),
("RECORDS", "DNS"),
("WHOIS", "WHOIS"),
("GENERAL", "DNS"), # default GENERAL to DNS unless overridden.
]

# Some TLS findings may belong to SMTP, not HTTP; we’ll re-route by task name.
TLS_TASK_HINTS_SMTP = {"smtp", "mail", "smtp_probe"}

# Traffic light thresholds
RATING_THRESHOLDS = {
"green": 90, # >= 90
"amber": 70, # 70–89
# else red
}

# -------------------------------
# Public API
# -------------------------------

def score_audit(tasks_findings: Mapping[str, List[Mapping]]) -> Dict[str, object]:
    """
    Compute scores for an audit.

    Parameters
    ----------
    tasks_findings: mapping of task_name -> list of finding dicts
    Each finding dict is expected to look like:
    {
    "code": str,
    "status": "ok|warn|fail|info|error",
    "title": str,
    "message": str,
    "remediation": str,
    "tags": [ "...", ... ],
    "references": [ ... ],
    "data": { ... },
    "evidence": { ... }
    }

    Returns
    -------
    dict with:
    - summary_score: float 0..100
    - rating: "green" | "amber" | "red"
    - area_scores: { area: {"weight": int, "deduction": float, "score": float, "findings": [codes...] } }
    - checklist: [ {code, status, title, message, remediation, area} ] (prioritized FAIL then WARN)
    - deductions: [ {area, code, status, penalty} ] (flat list)
    """
    _init_caps_if_needed()

    area_state: Dict[str, _AreaAccumulator] = {
        area: _AreaAccumulator(area=area, weight=AREA_WEIGHTS.get(area, 0))
        for area in AREA_WEIGHTS
    }
    deductions: List[Dict[str, object]] = []
    checklist: List[Dict[str, object]] = []

    for task_name, findings in tasks_findings.items():
        for f in findings or []:
            status = (f.get("status") or "info").lower()
            tags = {str(t).upper() for t in (f.get("tags") or [])}
            area = _classify_area(tags, task_name)

            # Unknown area? Put it in DNS bucket by default (safe fallback).
            if area not in area_state:
                area = "DNS"
                if "DNS" not in area_state:
                    area_state["DNS"] = _AreaAccumulator(area="DNS", weight=AREA_WEIGHTS.get("DNS", 0))

            penalty = _penalty_for(status, area)
            area_state[area].add_finding(f, penalty)

            if penalty > 0:
                deductions.append({"area": area, "code": f.get("code"), "status": status, "penalty": penalty})

            if status in ("fail", "warn"):
                checklist.append({
                    "area": area,
                    "code": f.get("code"),
                    "status": status,
                    "title": f.get("title"),
                    "message": f.get("message"),
                    "remediation": f.get("remediation"),
                })

    # Finalize per-area scores with caps
    total_weight = sum(a.weight for a in area_state.values())
    total_score = 0.0
    area_scores: Dict[str, Dict[str, object]] = {}

    for area, acc in area_state.items():
        cap = AREA_MAX_DEDUCTION.get(area, acc.weight)
        deduction = min(acc.deduction, cap)
        score = max(0.0, float(acc.weight) - float(deduction))
        total_score += score
        area_scores[area] = {
            "weight": acc.weight,
            "deduction": round(deduction, 2),
            "score": round(score, 2),
            "findings": acc.codes_sorted(),
        }

    # Normalize to 100 even if someone tweaks weights to not sum to 100
    summary_score = 0.0 if total_weight <= 0 else round((total_score / total_weight) * 100.0, 1)

    rating = _rating_for(summary_score)
    checklist_sorted = sorted(
        checklist,
        key=lambda x: (0 if x["status"] == "fail" else 1, x["area"], x["code"] or ""),
    )

    return {
        "summary_score": summary_score,
        "rating": rating,
        "area_scores": area_scores,
        "checklist": checklist_sorted,
        "deductions": deductions,
    }

# -------------------------------
# Internals
# -------------------------------

@dataclass
class _AreaAccumulator:
    area: str
    weight: int
    deduction: float = 0.0
    _codes: List[str] = None

    def add_finding(self, f: Mapping, penalty: float) -> None:
        if self._codes is None:
            self._codes = []
        code = str(f.get("code") or "")
        if code:
            self._codes.append(code)
        self.deduction += float(penalty)

    def codes_sorted(self) -> List[str]:
        return sorted(self._codes or [])

def _init_caps_if_needed() -> None:
    if AREA_MAX_DEDUCTION:
        return
    for area, w in AREA_WEIGHTS.items():
        AREA_MAX_DEDUCTION[area] = float(w)

def _classify_area(tags: Iterable[str], task_name: Optional[str]) -> str:
    # Heuristic: map based on tag priority
    tset = {t.upper() for t in tags}
    chosen: Optional[str] = None
    for tag, area in TAG_TO_AREA_ORDERED:
        if tag in tset:
            chosen = area or chosen
            if chosen:
                break

    # TLS routing hint: if task suggests SMTP, move TLS to SMTP
    if chosen == "HTTP" and task_name:
        tn = str(task_name).lower()
        if any(h in tn for h in TLS_TASK_HINTS_SMTP):
            chosen = "SMTP"

    return chosen or "DNS"

def _penalty_for(status: str, area: str) -> float:
    base = STATUS_BASE_PENALTY.get(status, 0.0)
    mult = AREA_PENALTY_MULTIPLIER.get(area, 1.0)
    # Scale penalty to be a fraction of area weight to keep things proportional.
    # Each "fail" roughly costs 15% of the area's weight by default (3.0 base * 0.05).
    # Tune SCALE if you want stricter/milder scoring.
    SCALE = 0.05
    area_weight = AREA_WEIGHTS.get(area, 0)
    return round(base * mult * SCALE * float(area_weight), 4)

def _rating_for(summary_score: float) -> str:
    if summary_score >= RATING_THRESHOLDS["green"]:
        return "green"
    return "amber" if summary_score >= RATING_THRESHOLDS["amber"] else "red"

# -------------------------------
# Example (manual test)
# -------------------------------
if __name__ == "__main__":
    sample = {
        "dns_records": [
            {"code": "A_PRESENT", "status": "ok", "title": "", "message": "", "remediation": "", "tags": ["DNS","RECORDS"]},
            {"code": "AAAA_MISSING", "status": "warn", "title": "", "message": "", "remediation": "", "tags": ["DNS","IPV6"]},
        ],
        "spf": [
            {"code": "SPF_PRESENT", "status": "ok", "title": "", "message": "", "remediation": "", "tags": ["SPF","EMAIL"]},
            {"code": "SPF_LOOKUP_COUNT_HIGH", "status": "warn", "title": "", "message": "", "remediation": "", "tags": ["SPF","EMAIL"], "data": {"count": 9}},
        ],
        "dmarc": [
            {"code": "DMARC_MISSING", "status": "fail", "title": "", "message": "", "remediation": "", "tags": ["DMARC","EMAIL"]},
        ],
        "dnssec": [
            {"code": "DNSSEC_NOT_ENABLED", "status": "warn", "title": "", "message": "", "remediation": "", "tags": ["DNSSEC","DNS"]},
        ],
        "smtp_probe": [
            {"code": "SMTP_STARTTLS_NOT_SUPPORTED", "status": "warn", "title": "", "message": "", "remediation": "", "tags": ["SMTP","TLS","EMAIL"]},
        ],
        "http_probe": [
            {"code": "HSTS_MISSING", "status": "warn", "title": "", "message": "", "remediation": "", "tags": ["HTTP","WEB","SECURITY"]},
        ],
        "whois": [
            {"code": "DOMAIN_EXPIRES_SOON", "status": "warn", "title": "", "message": "", "remediation": "", "tags": ["WHOIS","SECURITY"]},
        ],
    }
    result = score_audit(sample)
    from pprint import pprint
    pprint(result)
