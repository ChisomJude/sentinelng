"""
Tests for SentinelNG detection: discovery, classification, and the three
finding types. All offline, using fixture records rather than live CT data.
"""

from datetime import datetime, timedelta, timezone

from src.discovery import (
    contains_homoglyph,
    fold_homoglyphs,
    generate_tokens,
    is_own_asset,
    levenshtein,
    notable_labels_in,
    registrable_root,
    risky_labels_in,
)
from src.scoring import assess, score_impersonation, score_own_asset

CYRILLIC_A = "\u0430"
CYRILLIC_E = "\u0435"


def rec(domain, issuer="C=US, O=DigiCert Inc", days_valid=365, cid=1, age_days=30):
    nb = datetime.now(timezone.utc) - timedelta(days=age_days)
    na = nb + timedelta(days=days_valid)
    fmt = "%Y-%m-%dT%H:%M:%S"
    return {
        "domain": domain, "matched_token": "x", "issuer": issuer, "crtsh_id": cid,
        "not_before": nb.strftime(fmt), "not_after": na.strftime(fmt),
        "entry_timestamp": nb.strftime(fmt),
    }


# ------------------------------------------------------------ discovery

def test_registrable_root():
    assert registrable_root("www.gtbank.com") == "gtbank"
    assert registrable_root("staging.sterling.ng") == "sterling"


def test_token_generation_from_domain():
    tokens = generate_tokens(["sterling.ng"], include_impersonation=True)
    assert "sterling" in tokens


def test_tokens_drop_short_noise():
    assert all(len(t) >= 3 for t in generate_tokens(["ab.com"]))


def test_own_asset_and_subdomains():
    assert is_own_asset("pilot.sterling.ng", ["sterling.ng"])
    assert is_own_asset("sterling.ng", ["sterling.ng"])
    assert not is_own_asset("sterling-verify.xyz", ["sterling.ng"])


def test_own_asset_not_substring_fooled():
    assert not is_own_asset("notsterling.ng", ["sterling.ng"])


def test_risky_label_detection():
    assert any(lbl == "pilot" for lbl, _ in risky_labels_in("enf-pilot.sterling.ng"))
    assert any(lbl == "staging" for lbl, _ in risky_labels_in("staging-api.bank.com"))
    assert risky_labels_in("www.bank.com") == []


def test_notable_label_detection():
    assert any(lbl == "limesurvey" for lbl, _ in notable_labels_in("limesurvey.gtbank.com"))
    assert any(lbl == "livechat" for lbl, _ in notable_labels_in("livechat.gtbank.com"))


def test_homoglyph_helpers():
    assert contains_homoglyph(f"gtb{CYRILLIC_A}nk.com")
    assert contains_homoglyph("xn--gtbnk-w1a.com")
    assert not contains_homoglyph("gtbank.com")
    assert fold_homoglyphs(f"gtb{CYRILLIC_A}nk") == "gtbank"


def test_levenshtein():
    assert levenshtein("sterling", "sterling") == 0
    assert levenshtein("sterling", "sterlimg") == 1


# ---------------------------------------------------- own-asset scoring

def test_pilot_server_flagged_the_sterling_case():
    scored = score_own_asset(rec("enf-pilot.sterling.ng", age_days=2))
    assert scored["finding_type"] == "own_asset_risk"
    assert scored["risk_score"] >= 35
    assert any("pilot" in r for r in scored["reasons"])


def test_production_asset_scores_low():
    scored = score_own_asset(rec("www.sterling.ng"))
    assert scored["risk_score"] < 35


# -------------------------------------------------- impersonation scoring

def test_obvious_phishing_domain_is_critical():
    scored = score_impersonation(rec("sterling-verify-login.xyz", issuer="C=US, O=Let's Encrypt", age_days=0), "sterling", ["sterling.ng"])
    assert scored is not None
    assert scored["severity"] == "critical"


def test_homoglyph_domain_matches_brand():
    scored = score_impersonation(rec(f"st{CYRILLIC_E}rling-portal.top", issuer="C=US, O=Let's Encrypt"), "sterling", ["sterling.ng"])
    assert scored is not None
    assert scored["signals"]["homoglyph"] is True


def test_unrelated_domain_is_dropped():
    # A domain far from the brand returns None, not a noisy low-score finding.
    assert score_impersonation(rec("officialpayments.com"), "opay", ["opay.com"]) is None


# ------------------------------------------------------------ assess routing

def test_assess_routes_all_three_types():
    records = [
        rec("www.sterling.ng", cid=1),
        rec("enf-pilot.sterling.ng", cid=2, age_days=2),
        rec("sterling.ng", issuer="C=US, O=Let's Encrypt", days_valid=89, cid=3, age_days=1),
        rec("sterling-verify-login.xyz", issuer="C=US, O=Let's Encrypt", days_valid=89, cid=4, age_days=0),
    ]
    findings, stats = assess(records, ["sterling.ng"], min_score=35)
    types = {f["finding_type"] for f in findings}
    assert "own_asset_risk" in types
    assert "impersonation" in types
    assert "cert_anomaly" in types


def test_rogue_cert_not_masked_by_itself():
    # The baseline must come from long-lived commercial certs, so a fresh free
    # cert cannot teach the tool to expect itself.
    records = [
        rec("www.sterling.ng", issuer="C=US, O=DigiCert Inc", days_valid=365, cid=1),
        rec("sterling.ng", issuer="C=US, O=Let's Encrypt", days_valid=89, cid=2, age_days=1),
    ]
    findings, _ = assess(records, ["sterling.ng"], min_score=35)
    anomalies = [f for f in findings if f["finding_type"] == "cert_anomaly"]
    assert anomalies
    assert any("unexpected issuer" in r.lower() for r in anomalies[0]["reasons"])


def test_findings_carry_reasons():
    records = [rec("staging.sterling.ng", cid=1, age_days=2)]
    findings, _ = assess(records, ["sterling.ng"], min_score=35)
    assert findings
    assert all(f["reasons"] for f in findings)


def test_expired_but_live_cert_flagged():
    records = [
        rec("www.sterling.ng", days_valid=365, cid=1),
        rec("old-api.sterling.ng", days_valid=90, cid=2, age_days=120),  # expired 30d ago
    ]
    findings, _ = assess(records, ["sterling.ng"], min_score=35)
    # old-api has both a risky label and an expired cert
    assert any(f["domain"] == "old-api.sterling.ng" for f in findings)
