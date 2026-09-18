"""
Finding classification and risk scoring.

Every discovered certificate record is sorted into exactly one finding type:

  own_asset_risk   an asset the organisation owns whose name signals it is
                   forgotten or non-production. The Sterling Bank case.
  cert_anomaly     a certificate on the organisation's own domain from an
                   unexpected issuer, or an expiring/expired-but-live cert.
                   The GTBank domain-compromise case.
  impersonation    a lookalike domain the organisation does NOT own, built to
                   phish its customers.

Each finding is scored 0-100, banded, and carries a plain-language reason list
so a security team can act and justify the action.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .ct_client import parse_ct_timestamp
from .discovery import (
    PHISHING_KEYWORDS,
    contains_homoglyph,
    fold_homoglyphs,
    is_own_asset,
    levenshtein,
    notable_labels_in,
    registrable_root,
    risky_labels_in,
)

FREE_CA_MARKERS = ["let's encrypt", "zerossl", "buypass", "google trust services"]

HIGH_RISK_TLDS = {
    "xyz", "top", "online", "site", "club", "info", "click", "link", "live",
    "icu", "cyou", "shop", "store", "space", "fun", "buzz", "pw", "tk", "ml",
    "ga", "cf", "gq", "website", "rest", "monster", "sbs", "cfd", "bond",
}

# Shared hosting and CDN. An own-domain cert here is normal; a lookalike here
# is the classic free-infrastructure phishing pattern, so it is handled in
# context rather than blanket-suppressed.
SHARED_INFRA_SUFFIXES = [
    "cloudfront.net", "amazonaws.com", "azurewebsites.net", "cloudflare.net",
    "herokuapp.com", "vercel.app", "netlify.app", "github.io", "pages.dev",
    "workers.dev", "firebaseapp.com", "web.app", "hosted.app", "onrender.com",
    "fastly.net", "akamaized.net", "googleusercontent.com", "wixsite.com",
]

SEVERITY_BANDS = [(75, "critical"), (55, "high"), (35, "medium"), (0, "low")]


def _tld(domain: str) -> str:
    parts = domain.rsplit(".", 1)
    return parts[-1].lower() if len(parts) == 2 else ""


def _band(score: int) -> str:
    return next(label for threshold, label in SEVERITY_BANDS if score >= threshold)


def _cert_age_hours(record: dict[str, Any]) -> float | None:
    ts = parse_ct_timestamp(record.get("entry_timestamp")) or parse_ct_timestamp(record.get("not_before"))
    if not ts:
        return None
    return max((datetime.now(timezone.utc) - ts).total_seconds() / 3600.0, 0.0)


def _days_until_expiry(record: dict[str, Any]) -> float | None:
    ts = parse_ct_timestamp(record.get("not_after"))
    if not ts:
        return None
    return (ts - datetime.now(timezone.utc)).total_seconds() / 86400.0


def _finalise(record, ftype, score, reasons, signals):
    score = max(0, min(score, 100))
    return {
        **record,
        "finding_type": ftype,
        "risk_score": score,
        "severity": _band(score),
        "reasons": reasons,
        "signals": signals,
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }


def _issuer_org(issuer: str) -> str:
    issuer = (issuer or "").lower()
    return issuer.split("o=")[-1].split(",")[0].strip() if "o=" in issuer else ""


def _expected_issuer_orgs(records: list[dict[str, Any]], official_domains: list[str]) -> set[str]:
    """
    Learn which CA organisations normally issue for this estate.

    The baseline is built only from ESTABLISHED certificates: those with long
    validity periods (over 120 days), which commercial CAs like DigiCert issue
    and automated free CAs like Let's Encrypt (90-day max) do not. This matters
    because a domain-compromise attack provisions a fresh short-lived free cert,
    and if we learned the baseline from all certs indiscriminately, the rogue
    cert would teach us to expect itself. Building the baseline from the
    long-lived commercial certs the organisation actually bought avoids that.
    """
    orgs: set[str] = set()
    for r in records:
        if not is_own_asset(r["domain"], official_domains):
            continue
        nb = parse_ct_timestamp(r.get("not_before"))
        na = parse_ct_timestamp(r.get("not_after"))
        if nb and na and (na - nb).days > 120:
            org = _issuer_org(r.get("issuer", ""))
            if org:
                orgs.add(org)
    return orgs


def score_own_asset(record, reasons_prefix=None):
    """Score a hostname the organisation owns, by how risky its name is."""
    domain = record["domain"]
    risky = risky_labels_in(domain)
    score, reasons, signals = 0, list(reasons_prefix or []), {}

    if risky:
        score += 40 + 10 * (len(risky) - 1)
        for label, why in risky:
            reasons.append(f"Hostname label '{label}': {why}")
        signals["risky_labels"] = [lbl for lbl, _ in risky]

    notable = notable_labels_in(domain)
    if notable:
        score += 20 + 5 * (len(notable) - 1)
        for label, why in notable:
            reasons.append(f"Auxiliary service '{label}': {why}")
        signals["notable_labels"] = [lbl for lbl, _ in notable]

    age = _cert_age_hours(record)
    if age is not None and age <= 168:
        score += 15
        reasons.append("Certificate issued in the last 7 days, a newly exposed asset")
    signals["cert_age_hours"] = round(age, 1) if age is not None else None

    depth = record["domain"].count(".")
    if depth >= 3:
        score += 5
        reasons.append("Deeply nested hostname, often internal infrastructure")

    return _finalise(record, "own_asset_risk", score, reasons, signals)


def score_cert_anomaly(record, expected_orgs):
    """Score a certificate on an owned domain for issuer and expiry anomalies."""
    issuer = (record.get("issuer") or "").lower()
    issuer_org = issuer.split("o=")[-1].split(",")[0].strip() if "o=" in issuer else ""
    score, reasons, signals = 0, [], {"issuer_org": issuer_org}

    if expected_orgs and issuer_org and issuer_org not in expected_orgs:
        score += 55
        reasons.append(
            f"Certificate from an unexpected issuer '{issuer_org}'. This estate "
            f"normally uses: {', '.join(sorted(expected_orgs))}. Possible domain "
            f"or DNS compromise (the GTBank signature)."
        )
        age = _cert_age_hours(record)
        if age is not None and age <= 48:
            score += 15
            reasons.append("Unexpected certificate is less than 48 hours old")

    days = _days_until_expiry(record)
    signals["days_until_expiry"] = round(days, 1) if days is not None else None
    if days is not None:
        if days < 0:
            score += 30
            reasons.append("Certificate has expired but the asset is still certified in CT")
        elif days <= 14:
            score += 20
            reasons.append(f"Certificate expires in {int(days)} days, renewal risk")

    if score == 0:
        return None
    return _finalise(record, "cert_anomaly", score, reasons, signals)


def score_impersonation(record, org_root, official_domains):
    """Score a domain the organisation does NOT own for impersonation risk."""
    domain = record["domain"].lower()
    name = registrable_root(domain)
    flat = fold_homoglyphs(name).replace("-", "")
    score, reasons, signals = 0, [], {}

    exact = org_root in flat
    signals["brand_in_name"] = exact
    if exact:
        score += 30
        reasons.append(f"Registrable name contains '{org_root}' exactly")

    dist = levenshtein(flat, org_root)
    signals["edit_distance"] = dist
    if not exact and 0 < dist <= 2:
        score += 30
        reasons.append(f"Registrable name is {dist} edit(s) from '{org_root}'")
    elif not exact and dist <= 4:
        score += 15
        reasons.append(f"Registrable name is close to '{org_root}'")
    elif not exact:
        # Too far to be impersonation, likely an unrelated org sharing a substring.
        return None

    hits = sorted({k for k in PHISHING_KEYWORDS if k in domain})
    signals["keyword_hits"] = hits
    if hits:
        score += min(10 * len(hits), 25)
        reasons.append("Phishing keyword(s): " + ", ".join(hits))

    if contains_homoglyph(domain):
        score += 25
        reasons.append("Uses non-ASCII or punycode characters, visually deceptive")
    signals["homoglyph"] = contains_homoglyph(domain)

    issuer = (record.get("issuer") or "").lower()
    if any(m in issuer for m in FREE_CA_MARKERS) and exact:
        score += 10
        reasons.append("Free automated certificate authority on a brand lookalike")

    tld = _tld(domain)
    if tld in HIGH_RISK_TLDS:
        score += 15
        reasons.append(f"High-risk TLD: .{tld}")

    on_shared = any(domain.endswith(s) for s in SHARED_INFRA_SUFFIXES)
    if on_shared and exact:
        score += 15
        reasons.append("Brand name on free hosting infrastructure, a common phishing pattern")
    signals["on_shared_infra"] = on_shared

    age = _cert_age_hours(record)
    if age is not None and age <= 24:
        score += 10
        reasons.append("Certificate issued in the last 24 hours")

    return _finalise(record, "impersonation", score, reasons, signals)


def assess(
    records: list[dict[str, Any]],
    org_domains: list[str],
    min_score: int = 35,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """
    Classify and score every record. Returns (findings, stats).

    Routing per record:
      owned      -> own_asset_risk, and also cert_anomaly if the cert is odd
      not owned  -> impersonation (dropped if too far from the brand to matter)
    """
    org_root = registrable_root(org_domains[0]) if org_domains else ""
    expected_orgs = _expected_issuer_orgs(records, org_domains)

    findings: list[dict[str, Any]] = []
    stats = {"own_assets": 0, "impersonation_candidates": 0, "below_threshold": 0, "unrelated": 0}

    for record in records:
        owned = is_own_asset(record["domain"], org_domains)

        if owned:
            stats["own_assets"] += 1
            asset = score_own_asset(record)
            if asset["risk_score"] >= min_score:
                findings.append(asset)
            elif asset["risk_score"] > 0:
                stats["below_threshold"] += 1

            anomaly = score_cert_anomaly(record, expected_orgs)
            if anomaly and anomaly["risk_score"] >= min_score:
                findings.append(anomaly)
        else:
            imp = score_impersonation(record, org_root, org_domains)
            if imp is None:
                stats["unrelated"] += 1
            else:
                stats["impersonation_candidates"] += 1
                if imp["risk_score"] >= min_score:
                    findings.append(imp)
                else:
                    stats["below_threshold"] += 1

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (order[f["severity"]], -f["risk_score"]))
    return findings, stats
