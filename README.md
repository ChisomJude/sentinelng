# SentinelNG

**See every server, certificate and lookalike domain an attacker can find about your organisation, before they use it.**

SentinelNG watches public Certificate Transparency logs for your domains and tells your team, on every run, what is exposed: forgotten test servers, suspicious new certificates and fake domains built to phish your customers. It is fully passive and never touches your systems.

[Run it on Apify Store](https://apify.com/godstimechisom/sentinel) · [View the dashboard](https://sentinelng-three.vercel.app/)

---

## Why you need it

Breaches rarely start at the front door. They start with something nobody was watching:

- **A forgotten server.** In March 2026, attackers entered Sterling Bank through an unpatched pilot server (`enf-pilot.sterling.ng`). They stayed for nine days and pivoted into Remita, exposing about 900,000 customer records.
- **A hijacked domain.** In August 2024, attackers took control of `gtbank.com` the day after it was renewed and put a fake login page in front of customers.
- **A lookalike domain.** Fake domains with valid certificates are set up every week to phish bank and fintech customers by SMS, WhatsApp and paid search.

All three left a public trace the moment they began, because every website needs a TLS certificate and every certificate is published to public logs within minutes. SentinelNG reads those logs for you.

## Who it is for

Any organisation that holds sensitive data or assets and has a public web presence:

- Banks, microfinance banks and credit unions
- Fintechs, payment processors and PSPs
- Insurers, pension managers and asset managers
- Crypto, remittance and wallet operators
- Healthcare, government agencies, telcos and any enterprise handling personal or financial data

You don't need a security operations centre. If you own a domain, SentinelNG can watch it.

## What you get on every run

| What it finds | Why it matters |
|---|---|
| **Forgotten assets.** Pilot, staging, dev, test, legacy, VPN and admin hosts on your own domains | This is how Sterling was breached |
| **Certificate anomalies.** A fresh certificate on your main or login domain from an issuer you don't use | This is what the GTBank hijack looked like |
| **Impersonation.** Lookalike and homoglyph domains you don't own, built to phish your customers | Your customers lose money and your brand takes the blame |

Each finding has a 0 to 100 risk score, a severity (critical, high, medium or low) and a plain-language list of reasons, so your team can act on it and explain why.

Each run reports only what is new since the last one, so your team sees changes and not the same list again.

**Example:** run against `gtbank.com` using public data only, SentinelNG surfaces `gasset-pilot`, `gasset-dev`, `staging`, `cdn-staging` and `test-mbank`, all non-production environments on a live bank's domain.

## How to use it

Setup takes about two minutes. There's nothing to install and SentinelNG needs no access to your network.

1. **Open** [SentinelNG on Apify Store](https://apify.com/godstimechisom/sentinel) and click **Try for free**.
2. **Add your domains.** List every domain your organisation owns, including subsidiaries and regional domains (for example `yourbank.com`, `yourbank.ng`, `yourbank-ci.com`). Anything you leave out may be reported as a lookalike.
3. **Choose what to see.** Keep the default minimum score of 35 to see medium-risk findings and above, or lower it to 20 for your full asset inventory.
4. **Connect alerts (optional).** Paste a Slack, Microsoft Teams or other webhook URL, and pick which severities should trigger an alert.
5. **Click Start.** A run usually finishes within a few minutes. Findings appear in the **Output** tab, ranked by risk.
6. **Schedule it.** In Apify Console, open **Schedules** and set the Actor to run daily, weekly or monthly. Each run reports only what is new since the last one.

The first run gives you a full baseline and is the noisiest. If it flags a domain you legitimately own, add that domain to your list and later runs will treat it as yours.

### Input

| Field | Required | Default | What it does |
|---|---|---|---|
| `organization_domains` | Yes | | Domains your organisation owns, including subsidiaries |
| `min_score` | No | `35` | Findings scoring below this (0 to 100) are hidden. Use 20 for the full inventory |
| `detect_impersonation` | No | `true` | Also look for lookalike domains you don't own |
| `alert_severities` | No | `["critical", "high"]` | Which severities are sent to your webhook. Everything is still saved to the output |
| `webhook_url` | No | | Slack, Teams, SOAR or any HTTPS endpoint. Stored as a secret |
| `enable_fingerprint` | No | `false` | Advanced: one passive request to the homepage of each asset you own, to flag technologies with known CVEs |
| `use_apify_proxy` | No | `false` | Route log queries through Apify Proxy |

Sample input:

```json
{
  "organization_domains": ["yourbank.com", "yourbank.ng"],
  "min_score": 35,
  "detect_impersonation": true,
  "alert_severities": ["critical", "high"],
  "webhook_url": "https://hooks.slack.com/services/XXX/YYY/ZZZ"
}
```

### Output

Every run produces two outputs.

**1. Findings (dataset).** One item for each new finding, which you can view in the Output tab, export as JSON, CSV or Excel, or pull through the Apify API.

| Field | Description |
|---|---|
| `domain` | The asset or lookalike domain |
| `finding_type` | `own_asset_risk` (forgotten asset), `cert_anomaly` or `impersonation` |
| `risk_score` | 0 to 100 |
| `severity` | `critical`, `high`, `medium` or `low` |
| `reasons` | Plain-language reasons the asset was flagged |
| `signals` | The raw signals behind the score |
| `hostnames`, `hostname_count` | Every hostname grouped into this finding |
| `issuer` | The certificate authority that issued the certificate |
| `not_before`, `not_after` | Certificate validity window |
| `is_wildcard` | Whether the certificate covers `*.domain` |
| `cert_count`, `crtsh_ids` | Certificates seen, with their public crt.sh log IDs |
| `fingerprint` | Present only when `enable_fingerprint` is on |
| `detected_at` | When SentinelNG found it |

Sample finding:

```json
{
  "domain": "enf-pilot.internal.yourbank.ng",
  "finding_type": "own_asset_risk",
  "risk_score": 85,
  "severity": "critical",
  "reasons": [
    "Hostname label 'pilot': pilot or trial environment, often unpatched (the Sterling Bank signature)",
    "Hostname label 'internal': internally named asset that should not be internet facing",
    "Covered by a wildcard certificate, so one stolen private key or one compromised host authenticates every name under this domain",
    "Certificate issued in the last 7 days, a newly exposed asset"
  ],
  "signals": { "risky_labels": ["pilot", "internal"], "is_wildcard": true, "cert_age_hours": 11.0 },
  "hostnames": ["enf-pilot.internal.yourbank.ng"],
  "hostname_count": 1,
  "issuer": "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1",
  "not_before": "2026-09-24T10:33:59",
  "not_after": "2026-12-23T10:33:59",
  "is_wildcard": true,
  "cert_count": 1,
  "crtsh_ids": [9000000001],
  "detected_at": "2026-09-24T21:33:59+00:00"
}
```

**2. Run summary (key-value store, record `RUN_SUMMARY`).** Totals for the run, broken down by type and severity:

```json
{
  "organization": "yourbank.com",
  "run_at": "2026-10-09T06:00:12+00:00",
  "records_examined": 1240,
  "ct_complete": true,
  "findings": 37,
  "new_findings": 4,
  "by_type": { "own_asset_risk": 3, "cert_anomaly": 0, "impersonation": 1 },
  "by_severity": { "critical": 1, "high": 2, "medium": 1, "low": 0 }
}
```

If `ct_complete` is `false`, part of the log search failed during the run. Findings that depend on seeing an asset's full certificate history are held back until the next complete run.

The webhook sends `organization`, `run_at`, `alert_count` and the matching `findings` as JSON.

## Safe to buy, safe to run

- **100% passive.** It reads public records, the same logs every browser relies on. It never scans, probes or tests your infrastructure.
- **No access needed.** No credentials, agents or firewall changes.
- **Honest scope.** It detects exposure early. It does not patch servers or take down domains. It makes sure the thing that starts a breach is never something nobody was watching.

---

How detection works and the known limitations are covered in **[READMORE.md](READMORE.md)**.

Licence: MIT
