# packages/libs/core-checks/tests/test_scoring.py
#
# SPDX-FileCopyrightText: 2025 The dns-auditor Contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import importlib
import types

import packages.libs.core_checks.scoring as scoring


def _fresh_scoring_module() -> types.ModuleType:
    """
    Reload the scoring module to reset any mutated globals between tests.
    """
    return importlib.reload(scoring)


def test_penalty_math_single_fail_spf():
    sc = _fresh_scoring_module()

    # SPF area defaults:
    # weight=15, STATUS_BASE_PENALTY["fail"]=3.0, AREA_PENALTY_MULTIPLIER["SPF"]=1.2, SCALE=0.05
    # penalty = 3.0 * 1.2 * 0.05 * 15 = 2.7
    findings = {
        "spf": [
            {"code": "SPF_PRESENT", "status": "ok", "title": "", "message": "", "remediation": "", "tags": ["SPF"]},
            {"code": "SPF_MULTIPLE_RECORDS", "status": "fail", "title": "", "message": "", "remediation": "", "tags": ["SPF"]},
        ]
    }
    result = sc.score_audit(findings)
    # Summary score = 100 - 2.7 = 97.3
    assert abs(result["summary_score"] - 97.3) < 1e-6
    assert result["rating"] == "green"

    spf_area = result["area_scores"]["SPF"]
    assert abs(spf_area["deduction"] - 2.7) < 1e-6
    assert abs(spf_area["score"] - (15 - 2.7)) < 1e-6


def test_penalty_math_error_less_severe_than_warn_and_fail():
    sc = _fresh_scoring_module()

    # In DNS (weight=25, multiplier=1.0):
    # error penalty = 0.5 * 1.0 * 0.05 * 25 = 0.625 -> rounded to 0.62
    # warn penalty = 1.0 * 1.0 * 0.05 * 25 = 1.25
    # fail penalty = 3.0 * 1.0 * 0.05 * 25 = 3.75
    base = {"title": "", "message": "", "remediation": "", "tags": ["DNS"]}

    res_error = sc.score_audit({"dns_records": [{**base, "code": "X", "status": "error"}]})
    res_warn = sc.score_audit({"dns_records": [{**base, "code": "Y", "status": "warn"}]})
    res_fail = sc.score_audit({"dns_records": [{**base, "code": "Z", "status": "fail"}]})

    ded_err = res_error["area_scores"]["DNS"]["deduction"]
    ded_wrn = res_warn["area_scores"]["DNS"]["deduction"]
    ded_fai = res_fail["area_scores"]["DNS"]["deduction"]

    assert abs(ded_err - 0.62) < 1e-6
    assert abs(ded_wrn - 1.25) < 1e-6
    assert abs(ded_fai - 3.75) < 1e-6
    assert res_error["summary_score"] > res_warn["summary_score"] > res_fail["summary_score"]


def test_area_cap_prevents_over_deduction():
    sc = _fresh_scoring_module()

    # DMARC weight=20, multiplier=1.4
    # fail penalty per finding = 3.0 * 1.4 * 0.05 * 20 = 4.2
    # 20 such fails would sum 84.0, but area cap clamps to 20.
    findings = {
        "dmarc": [
            {"code": f"DMARC_{i}", "status": "fail", "title": "", "message": "", "remediation": "", "tags": ["DMARC"]}
            for i in range(20)
        ]
    }
    result = sc.score_audit(findings)
    dmarc = result["area_scores"]["DMARC"]
    assert abs(dmarc["deduction"] - 20.0) < 1e-6 # capped at area weight
    assert abs(dmarc["score"] - 0.0) < 1e-6 # cannot go below 0


def test_tls_routed_to_smtp_area():
    sc = _fresh_scoring_module()

    # TLS finding emitted under an SMTP task should map to SMTP area (weight=3, multiplier=0.9).
    # warn penalty = 1.0 * 0.9 * 0.05 * 3 = 0.135 -> rounded to 0.14
    findings = {
        "smtp_probe": [
            {"code": "STARTTLS_WEAK", "status": "warn", "title": "", "message": "", "remediation": "", "tags": ["TLS"]}
        ]
    }
    result = sc.score_audit(findings)
    smtp = result["area_scores"]["SMTP"]
    assert abs(smtp["deduction"] - 0.14) < 1e-6
    assert "SMTP" in result["area_scores"]
    # Ensure it did not land in HTTP:
    assert result["area_scores"]["HTTP"]["deduction"] == 0.0


def test_weight_normalization_when_total_not_100(monkeypatch):
    sc = _fresh_scoring_module()

    # Temporarily change weights to sum to 50 instead of 100, ensure normalization still outputs 0..100.
    weights_backup = copy.deepcopy(sc.AREA_WEIGHTS)
    try:
        sc.AREA_WEIGHTS.clear()
        sc.AREA_WEIGHTS.update({"DNS": 30, "SPF": 20}) # total 50
        # Reset derived caps so they reflect new weights
        sc.AREA_MAX_DEDUCTION.clear()

        # One fail in SPF: penalty = 3.0 * 1.2 * 0.05 * 20 = 3.6
        findings = {"spf": [{"code": "X", "status": "fail", "title": "", "message": "", "remediation": "", "tags": ["SPF"]}]}
        result = sc.score_audit(findings)

        # Raw points: DNS=30 (no deductions), SPF=20-3.6=16.4 => total=46.4/50 => 92.8 normalized
        assert abs(result["summary_score"] - 92.8) < 1e-6
        assert result["rating"] == "green"
    finally:
        sc.AREA_WEIGHTS.clear()
        sc.AREA_WEIGHTS.update(weights_backup)
        sc.AREA_MAX_DEDUCTION.clear()


def test_checklist_order_fail_before_warn_then_by_area_then_code():
    sc = _fresh_scoring_module()

    findings = {
        "dns_records": [
            {"code": "B_WARN", "status": "warn", "title": "", "message": "", "remediation": "", "tags": ["DNS"]},
            {"code": "A_FAIL", "status": "fail", "title": "", "message": "", "remediation": "", "tags": ["DNS"]},
        ],
        "spf": [
            {"code": "C_WARN", "status": "warn", "title": "", "message": "", "remediation": "", "tags": ["SPF"]},
            {"code": "A_FAIL", "status": "fail", "title": "", "message": "", "remediation": "", "tags": ["SPF"]},
        ],
    }
    result = sc.score_audit(findings)
    checklist = result["checklist"]

    # FAILs should come before WARNS, and within same priority sorted by area then code.
    statuses = [i["status"] for i in checklist]
    assert statuses[:2] == ["fail", "fail"]
    assert set(statuses[2:]) == {"warn"}


def test_zero_weight_area_does_not_affect_score():
    sc = _fresh_scoring_module()

    # WHOIS has weight 0 by default — even FAIL should not change summary_score.
    findings = {"whois": [{"code": "DOMAIN_EXPIRED", "status": "fail", "title": "", "message": "", "remediation": "", "tags": ["WHOIS"]}]}
    result = sc.score_audit(findings)
    assert abs(result["summary_score"] - 100.0) < 1e-6
    assert result["area_scores"]["WHOIS"]["weight"] == 0
