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
    "vpn":        "remote access gateway",
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


def registrable_root(domain: str) -> str:
    """
    The brand label of a domain. gtbank.com -> gtbank, sterling.ng -> sterling.
    Good enough for token generation without a public suffix list.
    """
    labels = domain.lower().strip().lstrip("*.").split(".")
    labels = [x for x in labels if x]
    if len(labels) >= 2:
        return labels[-2]
    return labels[0] if labels else ""


def generate_tokens(domains: list[str], include_impersonation: bool = True) -> list[str]:
    """
    Build CT search tokens from the organisation's own domains.

    The brand root (e.g. 'sterling') is the key token: a substring CT search on
    it returns the whole real estate plus most lookalikes in one query. When
    impersonation detection is on, a few hyphenation variants widen coverage.
    """
    tokens: set[str] = set()
    for domain in domains:
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
            if len(t) >= 5:
                extra.add(t[:-1])          # truncation typo
                extra.add(t + "-")         # hyphenated lookalike prefix
        tokens |= extra

    return sorted(t for t in tokens if len(t) >= 3)


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
