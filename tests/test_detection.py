"""
Tests for SentinelNG detection: discovery, classification, and the three
finding types. All offline, using fixture records rather than live CT data.
"""

from datetime import datetime, timedelta, timezone

from src.ct_client import extract_domains
from src.discovery import (
    NOTABLE_LABELS,
    RISKY_LABELS,
    contains_homoglyph,
    fold_homoglyphs,
    generate_tokens,
    is_own_asset,
    levenshtein,
    notable_labels_in,
    registrable_domain,
    registrable_root,
    risky_labels_in,
)
from src.scoring import (
    WILDCARD_BLAST_RADIUS,
    _issuer_org,
    assess,
    score_impersonation,
    score_own_asset,
)

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
        rec("sterling.ng", issuer="C=US, O=DigiCert Inc", days_valid=365, cid=5, age_days=300),
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
        # the asset's own established CA, which is what it is judged against
        rec("sterling.ng", issuer="C=US, O=DigiCert Inc", days_valid=365, cid=1, age_days=300),
        # the rogue: short-lived, so it cannot enter the history it is judged against
        rec("sterling.ng", issuer="C=US, O=Let's Encrypt", days_valid=89, cid=2, age_days=1),
    ]
    findings, _ = assess(records, ["sterling.ng"], min_score=35)
    anomalies = [f for f in findings if f["finding_type"] == "cert_anomaly"]
    assert anomalies
    assert any("established certificates come from" in r.lower() for r in anomalies[0]["reasons"])


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


# ------------------------------------------------- aggregation / false positives

def test_one_finding_per_domain_not_per_certificate():
    # CT keeps every cert an asset ever held. A live gtbank.com run returned the
    # same lookalike 92 times, once per cert. One asset must yield one row.
    records = [
        rec("gtbank-secure-login.xyz", issuer="C=US, O=Let's Encrypt", cid=i, age_days=1)
        for i in range(20)
    ]
    findings, _ = assess(records, ["gtbank.com"], min_score=20)
    lookalikes = [f for f in findings if f["domain"] == "gtbank-secure-login.xyz"]
    assert len(lookalikes) == 1
    assert lookalikes[0]["cert_count"] == 20


def test_merged_finding_keeps_strongest_evidence():
    # Evidence split across two certs must land on one row, scored on the worst.
    records = [
        rec("www.sterling.ng", issuer="C=US, O=DigiCert Inc", days_valid=365, cid=1),
        rec("sterling.ng", issuer="C=US, O=DigiCert Inc", days_valid=365, cid=2),
        rec("sterling.ng", issuer="C=US, O=Let's Encrypt", days_valid=89, cid=3, age_days=1),
    ]
    findings, _ = assess(records, ["sterling.ng"], min_score=35)
    anomalies = [f for f in findings if f["finding_type"] == "cert_anomaly"]
    assert len(anomalies) == 1
    assert anomalies[0]["domain"] == "sterling.ng"
    assert any("established certificates come from" in r.lower() for r in anomalies[0]["reasons"])


def test_healthy_asset_with_expired_history_is_not_flagged():
    # The false positive that marked 16 of 16 live GTBank assets: an asset with
    # a current cert AND expired older ones is healthy, not "expired".
    records = [
        rec("www.sterling.ng", days_valid=90, cid=1, age_days=400),  # long expired
        rec("www.sterling.ng", days_valid=90, cid=2, age_days=200),  # also expired
        rec("www.sterling.ng", days_valid=365, cid=3, age_days=10),  # current
    ]
    findings, _ = assess(records, ["sterling.ng"], min_score=20)
    expiry_reasons = [
        r for f in findings for r in f["reasons"] if "lapsed" in r or "expire" in r.lower()
    ]
    assert not expiry_reasons


def test_asset_whose_newest_cert_lapsed_is_still_flagged():
    # The true positive must survive the fix above.
    records = [
        rec("www.sterling.ng", days_valid=365, cid=1),
        rec("old-api.sterling.ng", days_valid=90, cid=2, age_days=200),
        rec("old-api.sterling.ng", days_valid=90, cid=3, age_days=400),
    ]
    findings, _ = assess(records, ["sterling.ng"], min_score=20)
    lapsed = [f for f in findings if f["domain"] == "old-api.sterling.ng"]
    assert lapsed
    assert any("lapsed" in r for f in lapsed for r in f["reasons"])


def test_no_valid_cert_claim_suppressed_on_incomplete_ct_data():
    # "This asset has no valid certificate" argues from absence, so it is only
    # sound when the CT sweep was complete. A failed token once left a live run
    # holding nothing newer than 2014 and it announced that www.gtbank.com had
    # no valid cert. Never make that claim on partial data.
    records = [
        rec("www.sterling.ng", days_valid=365, cid=1, age_days=400),  # stale snapshot
    ]
    findings, _ = assess(records, ["sterling.ng"], min_score=20, ct_complete=False)
    assert not [r for f in findings for r in f["reasons"] if "no currently valid" in r.lower()]


def test_long_dead_name_is_not_a_renewal_alert():
    # CT never forgets. A name decommissioned a decade ago must not alert forever.
    records = [rec("ancient.sterling.ng", days_valid=90, cid=1, age_days=4000)]
    findings, _ = assess(records, ["sterling.ng"], min_score=20, ct_complete=True)
    assert not [r for f in findings for r in f["reasons"] if "no currently valid" in r.lower()]


def test_recent_lapse_still_alerts_on_complete_data():
    # The true positive must survive both guards above.
    records = [
        rec("www.sterling.ng", days_valid=365, cid=1),
        rec("old-api.sterling.ng", days_valid=90, cid=2, age_days=150),  # lapsed 60d ago
    ]
    findings, _ = assess(records, ["sterling.ng"], min_score=20, ct_complete=True)
    assert [r for f in findings for r in f["reasons"] if "no currently valid" in r.lower()]


def test_estate_query_is_generated_and_left_intact():
    # '%.domain' is crt.sh's indexed subdomain form and the only query that
    # enumerates the estate completely. Measured live, '%gtbank%' returned 98
    # rows against 3902 for '%.gtbank.com'.
    tokens = generate_tokens(["gtbank.com"], include_impersonation=True)
    assert "%.gtbank.com" in tokens
    # brand roots still present, since a lookalike never sits under the org's domain
    assert "gtbank" in tokens
    # typo variants must not mangle the estate pattern
    assert not [t for t in tokens if t.startswith("%") and t != "%.gtbank.com"]


def test_estate_query_survives_short_brand_filter():
    # A two-letter brand is dropped as substring noise, but its estate query
    # must still run or the org gets no asset discovery at all.
    assert "%.ab.com" in generate_tokens(["ab.com"])


def test_issuer_org_survives_commas_inside_quoted_names():
    # Most CA names contain a comma and are therefore quoted in the DN. Splitting
    # on commas produced issuers called '"cpanel' and '"godaddy.com' in a live
    # run, which fragmented the learned baseline and flagged valid certs.
    assert _issuer_org('C=US, O="cPanel, Inc.", CN=cPanel, Inc. Certification Authority') == "cpanel, inc."
    assert _issuer_org('C=US, O="GoDaddy.com, Inc.", OU=x, CN=Go Daddy Secure CA') == "godaddy.com, inc."
    assert _issuer_org("C=US, O=DigiCert Inc, OU=www.digicert.com, CN=X") == "digicert inc"
    assert _issuer_org("O=Internet Security Research Group, CN=ISRG Root X1") == "internet security research group"
    assert _issuer_org("CN=no-org-here") == ""
    assert _issuer_org("") == ""


def test_same_ca_is_one_baseline_entry_not_two():
    # The fragmented parse meant one CA could look like two different issuers.
    quoted = 'C=US, O="cPanel, Inc.", CN=cPanel Root'
    records = [
        rec("a.sterling.ng", issuer=quoted, days_valid=365, cid=1),
        rec("b.sterling.ng", issuer=quoted, days_valid=365, cid=2),
        rec("c.sterling.ng", issuer=quoted, days_valid=365, cid=3),
    ]
    findings, _ = assess(records, ["sterling.ng"], min_score=20)
    unexpected = [
        r for f in findings for r in f["reasons"]
        if "established certificates come from" in r.lower()
    ]
    assert not unexpected


def test_asset_that_only_ever_used_a_free_ca_is_silent():
    # The estate-wide baseline could never learn a free CA, because it admits
    # only certs valid over 120 days and free CAs cap at 90. That made every
    # Let's Encrypt cert on gtbank.com high severity: 43 alerts that never clear.
    records = [
        rec("blog.sterling.ng", issuer="C=US, O=Let's Encrypt", days_valid=89, cid=i, age_days=i * 30)
        for i in range(1, 6)
    ]
    findings, _ = assess(records, ["sterling.ng"], min_score=20)
    assert not [f for f in findings if f["finding_type"] == "cert_anomaly"]


def test_pivot_away_from_an_assets_own_ca_is_caught():
    # The GTBank signature: an asset with years of commercial certs suddenly
    # answering to a fresh free one.
    records = [
        rec("sterling.ng", issuer="C=US, O=DigiCert Inc", days_valid=365, cid=1, age_days=700),
        rec("sterling.ng", issuer="C=US, O=DigiCert Inc", days_valid=365, cid=2, age_days=330),
        rec("sterling.ng", issuer="C=US, O=Let's Encrypt", days_valid=89, cid=3, age_days=1),
    ]
    findings, _ = assess(records, ["sterling.ng"], min_score=35)
    anomalies = [f for f in findings if f["finding_type"] == "cert_anomaly"]
    assert anomalies
    assert anomalies[0]["severity"] in ("high", "critical")


def test_impersonation_groups_by_registrable_domain():
    # One hostile registration is one thing to act on. A live run reported
    # gtbankci.com six times, once per subdomain.
    records = [
        rec("gtbankci.com", cid=1),
        rec("www.gtbankci.com", cid=2),
        rec("ebank.gtbankci.com", cid=3),
        rec("webapp.gtbankci.com", cid=4),
    ]
    findings, _ = assess(records, ["gtbank.com"], min_score=20)
    imp = [f for f in findings if f["finding_type"] == "impersonation"]
    assert len(imp) == 1
    assert imp[0]["domain"] == "gtbankci.com"
    assert imp[0]["hostname_count"] == 4
    assert "ebank.gtbankci.com" in imp[0]["hostnames"]


def test_owned_assets_are_not_grouped_together():
    # staging.x and www.x are separate units of risk and must stay separate.
    records = [
        rec("staging.sterling.ng", cid=1, age_days=2),
        rec("uat.sterling.ng", cid=2, age_days=2),
    ]
    findings, _ = assess(records, ["sterling.ng"], min_score=20)
    owned = {f["domain"] for f in findings if f["finding_type"] == "own_asset_risk"}
    assert owned == {"staging.sterling.ng", "uat.sterling.ng"}


def test_nigerian_second_level_domains_resolve_to_the_brand():
    # .com.ng is near-universal for the target market. Taking the second-to-last
    # label gave a brand root of 'com', which makes the CT token '%com%' and
    # matches every domain containing 'com' as a brand hit.
    assert registrable_root("firstbank.com.ng") == "firstbank"
    assert registrable_root("gtbank.com.ng") == "gtbank"
    assert registrable_domain("ebank.firstbank.com.ng") == "firstbank.com.ng"
    assert registrable_root("zenith.co.uk") == "zenith"
    assert registrable_root("sterling.ng") == "sterling"
    assert "com" not in generate_tokens(["firstbank.com.ng"])


# ------------------------------------------- unexpected issuer: recency + host

def _history_then(host, rogue_issuer, rogue_age_days, hist_age_days=1500):
    """A host with an established commercial CA, then one cert from elsewhere."""
    return [
        rec(host, issuer="C=US, O=DigiCert Inc", days_valid=365, cid=1, age_days=hist_age_days),
        rec(host, issuer=rogue_issuer, days_valid=89, cid=2, age_days=rogue_age_days),
    ]


def test_old_free_cert_on_marketing_subdomain_is_not_high():
    # The exact gtbank.com false positive: campaign.gtbank.com carried a Let's
    # Encrypt cert 1002 days old and scored 55 high. A migration that happened
    # nearly three years ago is not an incident.
    records = _history_then("campaign.sterling.ng", "C=US, O=Let's Encrypt", 1002)
    findings, _ = assess(records, ["sterling.ng"], min_score=20)
    anomalies = [f for f in findings if f["finding_type"] == "cert_anomaly"]
    assert anomalies
    assert anomalies[0]["severity"] == "low"
    assert anomalies[0]["risk_score"] == 20
    joined = " ".join(anomalies[0]["reasons"]).lower()
    assert "migration" in joined
    assert "compromise" not in joined


def test_fresh_free_cert_on_apex_is_critical():
    # The GTBank shape the tool exists to catch: the brand's own apex suddenly
    # answering to a CA it has never used.
    records = _history_then("sterling.ng", "C=US, O=Let's Encrypt", 0.5)
    findings, _ = assess(records, ["sterling.ng"], min_score=20)
    anomalies = [f for f in findings if f["finding_type"] == "cert_anomaly"]
    assert anomalies
    assert anomalies[0]["severity"] == "critical"
    assert "compromise" in " ".join(anomalies[0]["reasons"]).lower()


def test_fresh_free_cert_on_auth_host_is_high():
    # Not the apex, but where customers type their password.
    records = _history_then("login.sterling.ng", "C=US, O=Let's Encrypt", 0.5)
    findings, _ = assess(records, ["sterling.ng"], min_score=20)
    anomalies = [f for f in findings if f["finding_type"] == "cert_anomaly"]
    assert anomalies
    assert anomalies[0]["severity"] == "high"


def test_recency_alone_does_not_escalate():
    # A brand new cert on an ordinary subdomain is routine automation.
    records = _history_then("campaign.sterling.ng", "C=US, O=Let's Encrypt", 0.5)
    findings, _ = assess(records, ["sterling.ng"], min_score=20)
    anomalies = [f for f in findings if f["finding_type"] == "cert_anomaly"]
    assert anomalies
    assert anomalies[0]["severity"] == "low"


def test_sensitive_host_alone_does_not_escalate():
    # The apex matters, but not for a CA change that happened years ago.
    records = _history_then("sterling.ng", "C=US, O=Let's Encrypt", 1200)
    findings, _ = assess(records, ["sterling.ng"], min_score=20)
    anomalies = [f for f in findings if f["finding_type"] == "cert_anomaly"]
    assert anomalies
    assert anomalies[0]["severity"] == "low"


def test_every_gtbank_marketing_subdomain_drops_out_of_high():
    # All nine ordinary subdomains from the audited run, at their real ages.
    live = [("csr", 982), ("635", 982), ("sks", 997), ("campaign", 1002),
            ("fashionweekend", 1221), ("foodanddrink", 1512),
            ("shop.fashionweekend", 2075), ("prime", 2100), ("www", 1518)]
    for label, age in live:
        records = _history_then(f"{label}.sterling.ng", "C=US, O=Let's Encrypt", age,
                                hist_age_days=age + 400)
        findings, _ = assess(records, ["sterling.ng"], min_score=20)
        anomalies = [f for f in findings if f["finding_type"] == "cert_anomaly"]
        assert anomalies, label
        assert anomalies[0]["severity"] not in ("high", "critical"), f"{label} still escalates"


# ------------------------------------------------------- wildcard certificates

def _entry(*names):
    """A crt.sh entry whose SAN list holds `names`. crt.sh separates them with newlines."""
    return {"name_value": chr(10).join(names), "common_name": names[0]}


def test_wildcard_flag_survives_prefix_stripping():
    # The audit found this fact was fetched and thrown away: the "*." prefix was
    # stripped one line after it arrived, and nothing recorded that it had been there.
    assert extract_domains(_entry("*.gtbank.com")) == {"gtbank.com": True}
    assert extract_domains(_entry("www.gtbank.com")) == {"www.gtbank.com": False}


def test_wildcard_survives_pairing_with_the_plain_name():
    # One certificate routinely carries both forms, and both reduce to one host.
    # The wildcard must not be erased by whichever name is read second.
    assert extract_domains(_entry("*.gtbank.com", "gtbank.com")) == {"gtbank.com": True}
    assert extract_domains(_entry("gtbank.com", "*.gtbank.com")) == {"gtbank.com": True}


def test_wildcard_flag_reaches_a_mixed_san_list_correctly():
    got = extract_domains(_entry("*.a.gtbank.com", "b.gtbank.com"))
    assert got == {"a.gtbank.com": True, "b.gtbank.com": False}


def test_wildcard_raises_the_score_of_a_forgotten_asset():
    # A forgotten pilot host is bad. A forgotten pilot host holding a key that
    # authenticates the whole domain is worse, and the score should say so.
    plain = score_own_asset(rec("pilot.sterling.ng"))
    wild = score_own_asset(dict(rec("pilot.sterling.ng"), is_wildcard=True))
    assert wild["risk_score"] == plain["risk_score"] + WILDCARD_BLAST_RADIUS
    assert any("wildcard" in r.lower() for r in wild["reasons"])
    assert not any("wildcard" in r.lower() for r in plain["reasons"])


def test_wildcard_is_recorded_as_a_signal_either_way():
    assert score_own_asset(dict(rec("x.sterling.ng"), is_wildcard=True))["signals"]["is_wildcard"] is True
    assert score_own_asset(rec("x.sterling.ng"))["signals"]["is_wildcard"] is False


def test_wildcard_alone_does_not_manufacture_a_finding():
    # Wildcards are normal practice. On an ordinary host with no risky label the
    # signal must colour a finding, not create one above the threshold.
    records = [dict(rec("www.sterling.ng"), is_wildcard=True)]
    findings, stats = assess(records, ["sterling.ng"], min_score=35)
    assert not [f for f in findings if f["finding_type"] == "own_asset_risk"]
    assert stats["below_threshold"] >= 1


def test_wildcard_does_not_create_a_new_finding_type():
    records = [dict(rec("pilot.sterling.ng"), is_wildcard=True)]
    findings, _ = assess(records, ["sterling.ng"], min_score=20)
    assert {f["finding_type"] for f in findings} <= {"own_asset_risk", "cert_anomaly", "impersonation"}
    owned = [f for f in findings if f["finding_type"] == "own_asset_risk"]
    assert owned and any("wildcard" in r.lower() for r in owned[0]["reasons"])


# ---------------------------------------------------- label list hygiene (4a)

def test_no_label_is_both_risky_and_notable():
    # The general form of the bug. "vpn" sat in both lists, so a VPN host scored
    # +40 and +20 for one fact and carried two near-duplicate reasons. Guarding
    # the overlap rather than the single label stops it recurring with the next
    # entry somebody adds to either list.
    overlap = set(RISKY_LABELS) & set(NOTABLE_LABELS)
    assert not overlap, f"labels in both lists double-score: {sorted(overlap)}"


def test_vpn_host_scores_once_not_twice():
    scored = score_own_asset(rec("vpn.sterling.ng"))
    assert scored["risk_score"] == 40
    assert scored["severity"] == "medium"
    assert len([r for r in scored["reasons"] if "vpn" in r.lower()]) == 1
    assert scored["signals"]["risky_labels"] == ["vpn"]
    assert "notable_labels" not in scored["signals"]


def test_vpn_is_still_treated_as_risky():
    # Removing it from NOTABLE_LABELS must not quietly demote it out of scoring.
    assert "vpn" in RISKY_LABELS
    assert [lbl for lbl, _ in risky_labels_in("vpn.sterling.ng")] == ["vpn"]


# ------------------------------------------------- dead parameter removed (4b)

def test_score_own_asset_takes_only_a_record():
    import inspect
    params = list(inspect.signature(score_own_asset).parameters)
    assert params == ["record"], f"unexpected signature: {params}"
