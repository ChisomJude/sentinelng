# SentinelNG: technical detail

The [README](README.md) explains what SentinelNG is and who it is for. This page explains how detection works, how to run it locally and what it can't do. The input and output reference is in the README.

---

## Detection

### Discovery

The organisation's domains are turned into Certificate Transparency search tokens. One substring search on the brand root returns the whole real estate and most lookalikes. SentinelNG reads every certificate from both `name_value` and `common_name`, because crt.sh sometimes puts the hostname in only one of them. Wildcard certificates are kept as wildcards instead of being flattened, so their wider blast radius can be scored.

### Forgotten assets

Hostnames are classified by label. High-risk labels (`pilot`, `staging`, `dev`, `uat`, `test`, `legacy`, `old`, `bak`, `vpn`, `admin` and others) mark forgotten or non-production infrastructure. Auxiliary-service labels (`mail`, `livechat`, `limesurvey`, `servicedesk`, `ebank`, `webapp`) are listed for inventory, because third-party widgets and helpdesks are real attack surface. A wildcard certificate on an already-flagged asset raises its score. A wildcard on a healthy production host does not create a finding by itself.

### Certificate anomaly

An unexpected issuer on its own is not an alarm. Most of the web uses free authorities such as Let's Encrypt, and an old auto-renewing certificate is routine. On its own, an unexpected issuer scores low and is framed as a review prompt.

A finding escalates to high or critical only when the certificate was issued in the last 72 hours **and** sits on a sensitive host: the apex domain, or a host with an authentication or login label. Recent plus sensitive is the domain-compromise signature. Expired certificates that are still live are flagged for hygiene.

### Impersonation

Domains the organisation does not own are scored for brand containment, edit distance, phishing keywords, Unicode homoglyphs, high-risk TLDs, free certificate authorities and brand names on free hosting. Unicode lookalikes are folded to ASCII before matching. Domains too far from the brand to be plausible impersonation are dropped.

### Passive fingerprint (off by default)

An optional module sends one HTTP GET to the homepage of assets the operator owns. It reads only what the server volunteers in its headers and page, and matches the technology against known CVEs, as awareness ("verify your version"). It never probes, tests a vulnerability or requests any path other than the root. Confirming a vulnerability would require testing, which would be unauthorised access.

---

## Running locally

```bash
git clone https://github.com/ChisomJude/sentinelng.git
cd sentinelng

python -m venv .venv && source .venv/Scripts/activate   # Windows
pip install -r requirements.txt

apify login
apify run --input '{
  "organization_domains": ["gtbank.com", "gtbankci.com"],
  "min_score": 20,
  "detect_impersonation": true
}'
```

To deploy, push the Actor to Apify and set a schedule in the Console. See [DEPLOYMENT.md](DEPLOYMENT.md).

---

## Dashboard

Live at **https://sentinelng-three.vercel.app/**. It is a single static HTML file that reads directly from the Apify Dataset API, with no backend and no build step.

---

## Limitations

- **Detection, not remediation.** SentinelNG finds the exposure. Takedown and patching are separate workflows.
- **Passive by design.** It reports probable exposure from public data, never a confirmed vulnerability.
- **Publicly trusted certificates only.** An asset on plain HTTP or behind a private CA will not appear. In practice, exposed assets carry public certificates.
- **The domain-compromise signal depends on a new certificate.** That usually accompanies the attack, but not always.
- **Suppression needs tuning.** In the first week, expect to add legitimate subsidiaries and partners to the domain list.
- **crt.sh is a free community service.** Response times vary. Concurrency is kept low, and failures are retried and reported.

---

## Background

SentinelNG was first built for **Ship and Earn Africa**, the Apify x She Code Africa BuildHer Hackathon 2026 (Cybersecurity track).
