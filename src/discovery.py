"""
Asset discovery and hostname classification.

Two jobs:
  1. Turn an organisation's domain into the CT search tokens needed to find
     both its real estate and domains impersonating it.
  2. Classify each discovered hostname: is it the organisation's own asset,
     and if so does its name signal forgotten or non-production infrastructure.

The Sterling Bank breach began on enf-pilot.sterling.ng, a pilot server nobody
remembered was exposed. The risky-hostname classifier below is what surfaces
exactly that kind of asset.
"""

from __future__ import annotations

import re

# Hostname labels that signal non-production, forgotten, or sensitive assets.
# An attacker reads these the same way: they mark the soft targets.
RISKY_LABELS = {
    "pilot":    "pilot or trial environment, often unpatched (the Sterling Bank signature)",
    "staging":  "staging environment, frequently weaker controls than production",
    "stage":    "staging environment, frequently weaker controls than production",
    "dev":      "development environment exposed to the internet",
    "develop":  "development environment exposed to the internet",
    "test":     "test environment, often default credentials",
    "testing":  "test environment, often default credentials",
    "uat":      "user acceptance testing environment, pre-production",
    "qa":       "quality assurance environment, pre-production",
    "sandbox":  "sandbox environment",
    "demo":     "demo environment, often left running and unmaintained",
    "old":      "name suggests a superseded asset that may be unmaintained",
    "legacy":   "legacy asset, likely running outdated software",
    "bak":      "backup asset, may expose data or old code",
    "backup":   "backup asset, may expose data or old code",
    "tmp":      "temporary asset that may have outlived its purpose",
    "temp":     "temporary asset that may have outlived its purpose",
    "vpn":      "remote access gateway, a high value target",
    "admin":    "administrative interface exposed to the internet",
    "internal": "internally named asset that should not be internet facing",
    "intranet": "intranet asset that should not be internet facing",
    "jenkins":  "CI server, a common initial access point",
    "gitlab":   "source control, sensitive if exposed",
    "jira":     "internal tooling exposed to the internet",
    "grafana":  "monitoring dashboard, often unauthenticated",
    "kibana":   "log dashboard, often unauthenticated",
}


# Assets worth surfacing for inventory even when not high-risk on their own.
# Third-party and auxiliary services are real attack surface: LimeSurvey,
# live-chat widgets, webmail and service desks have all been breach vectors.
NOTABLE_LABELS = {
    "mail":       "mail service, credential and phishing target",
    "webmail":    "webmail interface, credential target",
    "limesurvey": "third-party survey software, historically vulnerable",
    "survey":     "third-party survey tool, external code",
    "livechat":   "third-party chat widget, external code in the page",
    "chat":       "third-party chat widget, external code in the page",
    "servicedesk":"helpdesk system, often internet-facing and sensitive",
    "helpdesk":   "helpdesk system, often internet-facing and sensitive",
    # NOTE: "vpn" is deliberately absent. It lives in RISKY_LABELS, and
    # listing it here too made every VPN host score twice, +40 and +20,
    # for one fact, with two near-duplicate reasons on the finding.
    "remote":     "remote access service",
    "portal":     "customer or partner portal, authentication surface",
    "ebank":      "online banking application, high-value surface",
    "webapp":     "web application server, review whether still in use",
}

# Phishing keywords used when scoring lookalike (impersonation) domains.
PHISHING_KEYWORDS = [
    "verify", "login", "secure", "portal", "update", "account", "otp",
    "token", "confirm", "support", "alert", "online", "auth", "signin",
    "customer", "bvn", "transfer", "wallet", "payment", "upgrade",
]


# Two-label public suffixes. Taking the second-to-last label as the brand is
# correct for gtbank.com but wrong for every one of these: firstbank.com.ng
# would yield 'com'. That is not academic for this product. Nigerian banks sit
# on .com.ng almost universally, and a brand root of 'com' makes the CT token
# '%com%' and makes every domain containing 'com' score as a brand match.
# A full public suffix list is overkill here; this covers the target market
# and the common international suffixes.
MULTI_LABEL_SUFFIXES = {
    "com.ng", "org.ng", "gov.ng", "edu.ng", "net.ng", "sch.ng", "mil.ng", "name.ng",
    "com.gh", "com.ke", "co.ke", "com.za", "co.za", "org.za", "com.eg", "com.tz",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "co.nz", "co.in", "co.jp", "com.br", "com.cn",
    "com.tr", "com.mx", "com.ar", "com.sg", "com.my", "com.ph", "com.pk",
}


def _split_suffix(domain: str) -> tuple[list[str], str]:
    """Return (labels before the public suffix, the suffix)."""
    labels = [x for x in domain.lower().strip().lstrip("*.").split(".") if x]
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return labels[:-2], ".".join(labels[-2:])
    if len(labels) >= 2:
        return labels[:-1], labels[-1]
    return labels, ""


def registrable_root(domain: str) -> str:
    """
    The brand label of a domain. gtbank.com -> gtbank, sterling.ng -> sterling,
    and firstbank.com.ng -> firstbank rather than 'com'.
    """
    head, _ = _split_suffix(domain)
    return head[-1] if head else ""


def registrable_domain(domain: str) -> str:
    """
    The domain someone actually registered, suffix included.

    ebank.gtbankci.com -> gtbankci.com. Impersonation findings group on this,
    because one hostile registration is one thing to act on no matter how many
    hostnames the attacker hangs off it.
    """
    head, suffix = _split_suffix(domain)
    if not head:
        return suffix
    return f"{head[-1]}.{suffix}" if suffix else head[-1]


def generate_tokens(domains: list[str], include_impersonation: bool = True) -> list[str]:
    """
    Build CT search tokens from the organisation's own domains.

    Two kinds of query, because neither alone is sufficient.

    '%.sterling.ng' is crt.sh's indexed subdomain form and is what actually
    enumerates the estate. A bare substring search cannot replace it: crt.sh
    silently truncates expensive LIKE queries, and measured against real data
    '%gtbank%' returned 98 rows where '%.gtbank.com' returned 3902. Scoring the
    truncated 2.5% is what made a live run report that www.gtbank.com had no
    valid certificate, on the strength of a 2014 cert.

    The brand root ('sterling') is still needed, because a lookalike lives on
    someone else's domain and so can never appear under '%.sterling.ng'. It is
    an impersonation query only, and its truncation is tolerable there: it is
    looking for the presence of a hostile name, not the absence of a friendly one.
    """
    tokens: set[str] = set()
    for domain in domains:
        clean_domain = domain.lower().strip().lstrip("*.")
        if clean_domain and "." in clean_domain:
            # Indexed estate enumeration. Kept verbatim by the CT client.
            tokens.add(f"%.{clean_domain}")
        root = registrable_root(domain)
        if len(root) >= 3:
            tokens.add(root)
        # full domain too, so subsidiaries on other TLDs still resolve
        clean = domain.lower().strip().lstrip("*.")
        if clean:
            tokens.add(clean.split(".")[0])

    if include_impersonation:
        extra: set[str] = set()
        for t in list(tokens):
            # Typo variants apply to brand roots only. Mutating the indexed
            # estate pattern would just produce nonsense like '%.gtbank.co'.
            if t.startswith("%"):
                continue
            if len(t) >= 5:
                extra.add(t[:-1])          # truncation typo
                extra.add(t + "-")         # hyphenated lookalike prefix
        tokens |= extra

    return sorted(t for t in tokens if t.startswith("%") or len(t) >= 3)


def is_own_asset(domain: str, official_domains: list[str]) -> bool:
    """True if the hostname sits under one of the organisation's own domains."""
    domain = domain.lower().strip().lstrip("*.")
    for official in official_domains:
        official = official.lower().strip().lstrip("*.")
        if not official:
            continue
        if domain == official or domain.endswith("." + official):
            return True
    return False


def risky_labels_in(domain: str) -> list[tuple[str, str]]:
    """
    Return (label, reason) for every risky token in the hostname.
    Matches on dot- or hyphen-delimited labels so 'enf-pilot' hits 'pilot'.
    """
    parts = re.split(r"[.\-_]", domain.lower())
    return [(lbl, RISKY_LABELS[lbl]) for lbl in parts if lbl in RISKY_LABELS]


# ------------------------------------------------------------------ homoglyph

HOMOGLYPH_MAP = {
    "a": "\u0430", "c": "\u0441", "e": "\u0435", "o": "\u043e",
    "p": "\u0440", "x": "\u0445", "y": "\u0443", "i": "\u0456",
    "s": "\u0455", "k": "\u043a",
}
_FOLD = {v: k for k, v in HOMOGLYPH_MAP.items()}


def contains_homoglyph(domain: str) -> bool:
    if "xn--" in domain.lower():
        return True
    return any(ord(c) > 127 for c in domain)


def fold_homoglyphs(text: str) -> str:
    return "".join(_FOLD.get(c, c) for c in text)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]

def notable_labels_in(domain: str) -> list[tuple[str, str]]:
    """Return (label, reason) for auxiliary/third-party service labels worth inventorying."""
    parts = re.split(r"[.\\-_]", domain.lower())
    return [(lbl, NOTABLE_LABELS[lbl]) for lbl in parts if lbl in NOTABLE_LABELS]
