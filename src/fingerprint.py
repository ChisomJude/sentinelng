"""
Passive technology fingerprinting, OFF BY DEFAULT.

LEGAL BOUNDARY. This module performs a single HTTP GET to the root of an asset
and reads only what the server volunteers in its response headers and homepage,
exactly what any browser or search crawler receives. It never probes, never
tests a vulnerability, never sends a crafted payload, never touches a path other
than "/".

It runs ONLY against assets the operator owns (own_asset findings), and only
when explicitly enabled. It correlates a public fingerprint against a small
table of known high-profile CVEs and reports "runs a technology with a known
CVE, verify your version" as AWARENESS. It never asserts that an asset IS
vulnerable, because confirming that would require testing, which would be
unauthorised access on infrastructure the operator may not own.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

# Small, hand-maintained table of high-profile 2024-2026 CVEs keyed by the
# technology token that appears in a Server or X-Powered-By header, or page.
# Awareness only: presence of the technology, not proof of vulnerability.
CVE_TABLE = {
    "next.js": [
        {"cve": "CVE-2025-29927", "note": "Next.js middleware authorization bypass", "severity": "critical"},
    ],
    "apache": [
        {"cve": "CVE-2024-38476", "note": "Apache HTTP Server, multiple 2.4.x RCE/SSRF issues", "severity": "high"},
    ],
    "openssl": [
        {"cve": "CVE-2024-6119", "note": "OpenSSL denial of service in certificate name checks", "severity": "high"},
    ],
    "php": [
        {"cve": "CVE-2024-4577", "note": "PHP-CGI argument injection RCE on Windows", "severity": "critical"},
    ],
    "nginx": [
        {"cve": "CVE-2024-7347", "note": "nginx mp4 module memory overwrite", "severity": "medium"},
    ],
    "iis": [
        {"cve": "CVE-2025-55182", "note": "Referenced in the Sterling Bank chain breach analysis", "severity": "critical"},
    ],
}

FINGERPRINT_PATTERNS = {
    "next.js": re.compile(r"next\.js|/_next/|x-powered-by:\s*next", re.I),
    "apache": re.compile(r"server:\s*apache|apache/[\d.]+", re.I),
    "nginx": re.compile(r"server:\s*nginx|nginx/[\d.]+", re.I),
    "php": re.compile(r"x-powered-by:\s*php|php/[\d.]+", re.I),
    "iis": re.compile(r"server:\s*microsoft-iis|iis/[\d.]+", re.I),
    "openssl": re.compile(r"openssl/[\d.]+", re.I),
}


async def fingerprint_asset(domain: str, timeout: float = 10.0) -> dict[str, Any] | None:
    """
    One GET to https://<domain>/. Read headers and a slice of the body.
    Returns detected technologies and correlated CVEs, or None on any failure.
    Failure is silent by design: this is best-effort awareness, not a scanner.
    """
    url = f"https://{domain}/"
    headers_text = ""
    body_slice = ""
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "SentinelNG/1.0 (asset owner self-assessment)"},
        ) as client:
            resp = await client.get(url)
            headers_text = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            body_slice = resp.text[:4000]
    except Exception:  # noqa: BLE001 - passive, never raises upward
        return None

    haystack = headers_text + "\n" + body_slice
    detected: list[str] = []
    for tech, pattern in FINGERPRINT_PATTERNS.items():
        if pattern.search(haystack):
            detected.append(tech)

    if not detected:
        return None

    awareness: list[dict[str, Any]] = []
    for tech in detected:
        for entry in CVE_TABLE.get(tech, []):
            awareness.append({
                "technology": tech,
                "cve": entry["cve"],
                "severity": entry["severity"],
                "note": entry["note"],
                "advisory": (
                    f"This asset appears to run {tech}, which has a known "
                    f"{entry['severity']} issue ({entry['cve']}). Verify your "
                    f"version is patched. This is awareness from public data, "
                    f"not a confirmation that the asset is vulnerable."
                ),
            })

    return {
        "server_header": _header_value(headers_text, "server"),
        "powered_by": _header_value(headers_text, "x-powered-by"),
        "technologies": detected,
        "cve_awareness": awareness,
    }


def _header_value(headers_text: str, name: str) -> str | None:
    for line in headers_text.split("\n"):
        if line.lower().startswith(name.lower() + ":"):
            return line.split(":", 1)[1].strip()
    return None
