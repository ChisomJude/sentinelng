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

import re
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
    registrable_domain,
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

# A certificate that lapsed longer ago than this is treated as dead history
# rather than a renewal failure. CT never forgets, so every long-decommissioned
# name stays in the log forever and would otherwise alert forever.
STALE_HISTORY_DAYS = 365


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
    """
    Pull the O= organisation out of a certificate issuer DN.

    The value is quoted whenever it contains a comma, which most CA names do:
    'C=US, O="cPanel, Inc.", CN=...'. Splitting the DN on commas therefore cuts
    the name in half and keeps the opening quote, which is how a live run came
    to report issuers named '"cpanel', '"godaddy.com' and '"verisign'. Those
    fragments then fail to match the same CA seen elsewhere, so the learned
    baseline fragments too and legitimate certificates get flagged as coming
    from an unexpected issuer.
    """
    match = re.search(r'(?:^|[, ])O=("([^"]*)"|[^,]*)', issuer or "", re.IGNORECASE)
    if not match:
        return ""
    value = match.group(2) if match.group(2) is not None else match.group(1)
    return value.strip().lower()


def _issuer_history_by_asset(
    records: list[dict[str, Any]], official_domains: list[str]
) -> dict[str, set[str]]:
    """
    Per-asset record of which CAs have issued long-lived certificates for it.

    Judged per asset rather than across the estate. An estate-wide baseline
    cannot tell "this organisation never uses Let's Encrypt" from "this
    organisation uses Let's Encrypt on forty subdomains", and since the
    baseline only admits certs valid over 120 days while free CAs cap at 90,
    no automated CA can ever enter it. Against live gtbank.com data that made
    every Let's Encrypt and cPanel certificate on the estate permanently high
    severity: 43 standing alerts that would never clear.

    Per asset the question sharpens into the one that matches the attack. An
    asset that has been on DigiCert for years and suddenly answers to a fresh
    free cert has had something done to it. An asset that has only ever used a
    free CA is simply run that way, and says nothing. The 120-day floor still
    does the work it was added for: a rogue short-lived cert cannot write
    itself into the history it is about to be judged against.
    """
    history: dict[str, set[str]] = {}
    for r in records:
        if not is_own_asset(r["domain"], official_domains):
            continue
        nb = parse_ct_timestamp(r.get("not_before"))
        na = parse_ct_timestamp(r.get("not_after"))
        if nb and na and (na - nb).days > 120:
            org = _issuer_org(r.get("issuer", ""))
            if org:
                history.setdefault(r["domain"], set()).add(org)
    return history


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


def score_cert_anomaly(record, asset_history, latest_expiry=None, ct_complete=True):
    """Score a certificate on an owned domain for issuer and expiry anomalies.

    Expiry is judged per DOMAIN, not per certificate. Certificate Transparency
    is append-only: every cert an estate has ever held stays in the log forever,
    and most of them are expired by definition. Scoring expiry per record
    therefore flags every healthy asset. Against live gtbank.com data it did
    exactly that: 16 of 16 owned assets reported as "expired", all false.
    `latest_expiry` carries the furthest not_after seen for this domain across
    all its certs, so we only report an asset whose newest cert has actually
    lapsed.

    `ct_complete` guards the same claim against partial data. "This asset has
    no valid certificate" is an argument from absence: it is only sound if we
    actually saw the asset's whole certificate history. When a CT token fails
    we have not. A live gtbank.com run where the `gtbank` token timed out left
    us holding nothing newer than 2014, and the scorer duly announced that
    www.gtbank.com had no valid certificate, which is false and is the kind of
    finding that destroys trust in the tool. Issuer anomalies are arguments
    from evidence present, so they still stand on partial data.
    """
    issuer_org = _issuer_org(record.get("issuer", ""))
    score, reasons, signals = 0, [], {"issuer_org": issuer_org}

    if asset_history and issuer_org and issuer_org not in asset_history:
        score += 55
        reasons.append(
            f"Certificate from '{issuer_org}', which has never issued for this asset. "
            f"Its established certificates come from: {', '.join(sorted(asset_history))}. "
            f"A switch away from an asset's own long-standing CA is the GTBank "
            f"signature: possible domain or DNS compromise."
        )
        age = _cert_age_hours(record)
        if age is not None and age <= 48:
            score += 15
            reasons.append("Unexpected certificate is less than 48 hours old")

    days = _days_until_expiry(record)
    if latest_expiry is not None:
        days = (latest_expiry - datetime.now(timezone.utc)).total_seconds() / 86400.0
    signals["days_until_expiry"] = round(days, 1) if days is not None else None
    signals["ct_complete"] = ct_complete
    if days is not None and not ct_complete and days < 0:
        # Cannot distinguish "genuinely lapsed" from "we never fetched the
        # current cert". Say nothing rather than say something false.
        days = None
    if days is not None and days < -STALE_HISTORY_DAYS:
        # Nothing has been issued for this name in years. That is a dead record
        # in an append-only log, not a renewal failure a team can act on. The
        # forgotten-asset angle is own_asset_risk's job, scored on the name.
        days = None
    if days is not None:
        if days < 0:
            score += 30
            reasons.append(
                f"No currently valid certificate: the newest one lapsed "
                f"{abs(int(days))} days ago, yet the asset is still published in CT"
            )
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


def _latest_expiry_by_domain(records: list[dict[str, Any]]) -> dict[str, datetime]:
    """Furthest not_after per domain, so expiry is judged on the newest cert."""
    latest: dict[str, datetime] = {}
    for r in records:
        na = parse_ct_timestamp(r.get("not_after"))
        if not na:
            continue
        d = r["domain"]
        if d not in latest or na > latest[d]:
            latest[d] = na
    return latest


def _merge_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Collapse to one finding per (finding_type, domain).

    Certificate Transparency stores every certificate an asset has ever been
    issued, so a single domain routinely produces dozens of records. Emitting
    one finding per record buries the signal: a live gtbank.com run produced 92
    impersonation findings that were all the same domain, gtbankci.com, ninety-two
    times over. A security team needs one row per asset, carrying the strongest
    evidence found across its certificate history.

    The surviving row is the highest-scoring one. Reasons are unioned so
    evidence spread across several certs (an odd issuer on one, a fresh cert on
    another) lands on the same row, and cert_count records how much history
    backs it.
    """
    merged: dict[tuple[str, str], dict[str, Any]] = {}

    for f in findings:
        # Impersonation groups on the registrable domain. One hostile
        # registration is one thing to act on, however many hostnames the
        # attacker hangs off it: a live run reported gtbankci.com six times,
        # once per subdomain. Owned assets stay per hostname, because there the
        # individual host IS the unit of risk (staging.x and www.x are not one
        # finding).
        group = (
            registrable_domain(f["domain"])
            if f["finding_type"] == "impersonation"
            else f["domain"]
        )
        key = (f["finding_type"], group)
        current = merged.get(key)
        if current is None:
            winner, loser = dict(f), None
        elif f["risk_score"] > current["risk_score"]:
            winner, loser = dict(f), current
        else:
            winner, loser = current, f

        winner.setdefault("hostnames", [])
        for host in [f["domain"], *(f.get("hostnames") or [])]:
            if host not in winner["hostnames"]:
                winner["hostnames"].append(host)
        if loser is not None:
            for host in [loser["domain"], *(loser.get("hostnames") or [])]:
                if host not in winner["hostnames"]:
                    winner["hostnames"].append(host)
            seen = set(winner["reasons"])
            winner["reasons"] = winner["reasons"] + [r for r in loser["reasons"] if r not in seen]
            winner["cert_count"] = winner.get("cert_count", 1) + loser.get("cert_count", 1)
            ids = winner.get("crtsh_ids") or ([winner["crtsh_id"]] if winner.get("crtsh_id") else [])
            for cid in (loser.get("crtsh_ids") or ([loser["crtsh_id"]] if loser.get("crtsh_id") else [])):
                if cid not in ids:
                    ids.append(cid)
            winner["crtsh_ids"] = ids[:10]
        else:
            winner.setdefault("cert_count", 1)
            winner["crtsh_ids"] = [winner["crtsh_id"]] if winner.get("crtsh_id") else []

        winner["domain"] = group
        winner["hostname_count"] = len(winner["hostnames"])
        winner["hostnames"] = winner["hostnames"][:20]
        merged[key] = winner

    return list(merged.values())


def assess(
    records: list[dict[str, Any]],
    org_domains: list[str],
    min_score: int = 35,
    ct_complete: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """
    Classify and score every record. Returns (findings, stats).

    Routing per record:
      owned      -> own_asset_risk, and also cert_anomaly if the cert is odd
      not owned  -> impersonation (dropped if too far from the brand to matter)
    """
    org_root = registrable_root(org_domains[0]) if org_domains else ""
    issuer_history = _issuer_history_by_asset(records, org_domains)
    latest_expiry = _latest_expiry_by_domain(records)

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

            anomaly = score_cert_anomaly(
                record,
                issuer_history.get(record["domain"], set()),
                latest_expiry.get(record["domain"]),
                ct_complete,
            )
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

    findings = _merge_findings(findings)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: (order[f["severity"]], -f["risk_score"]))
    return findings, stats
