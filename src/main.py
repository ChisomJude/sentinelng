"""
SentinelNG - Apify Actor entrypoint.

External attack surface monitoring for financial institutions, built on public
Certificate Transparency logs. Give it your own domain; it returns the
attacker's outside view of your estate: forgotten assets, certificate
anomalies, and impersonation domains.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx
from apify import Actor

from .ct_client import query_all_tokens
from .discovery import generate_tokens, is_own_asset
from .fingerprint import fingerprint_asset
from .scoring import assess

STATE_STORE_NAME = "sentinelng-state"
STATE_KEY = "seen-findings"
MAX_STATE_ENTRIES = 50_000


async def load_seen(store) -> set[str]:
    stored = await store.get_value(STATE_KEY)
    return set(stored.get("keys", [])) if stored else set()


async def save_seen(store, seen: set[str]) -> None:
    await store.set_value(STATE_KEY, {
        "keys": list(seen)[-MAX_STATE_ENTRIES:],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    })


def fingerprint_key(f: dict[str, Any]) -> str:
    """
    Identity of a finding across runs, for the seen-before diff.

    Keyed on the asset and its severity, NOT on the certificate id. Keying on
    the cert id meant every routine renewal minted a brand new "finding" for an
    asset the team had already triaged, so a single lookalike domain could
    re-alert on every run. Including severity keeps the one alert that matters:
    if an asset escalates from medium to critical, that is new information and
    fires again.
    """
    return f"{f['finding_type']}|{f['domain']}|{f['severity']}"


async def deliver_webhook(url: str, payload: dict[str, Any]) -> bool:
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.post(url, json=payload)
            r.raise_for_status()
        return True
    except Exception as exc:  # noqa: BLE001
        Actor.log.warning(f"Webhook delivery failed: {exc}")
        return False


async def main() -> None:
    async with Actor:
        actor_input = await Actor.get_input() or {}

        org_domains = [
            d.strip().lower().lstrip("*.")
            for d in actor_input.get("organization_domains", [])
            if d and d.strip()
        ]
        if not org_domains:
            raise ValueError("organization_domains is required (your own domains)")

        min_score = int(actor_input.get("min_score", 35))
        detect_impersonation = bool(actor_input.get("detect_impersonation", True))
        alert_severities = actor_input.get("alert_severities", ["critical", "high"])
        webhook_url = actor_input.get("webhook_url")
        use_proxy = bool(actor_input.get("use_apify_proxy", False))

        # OFF BY DEFAULT. Own assets only. See fingerprint.py for the legal note.
        enable_fingerprint = bool(actor_input.get("enable_fingerprint", False))

        Actor.log.info(
            f"SentinelNG monitoring {org_domains} | min_score={min_score} | "
            f"impersonation={detect_impersonation} | fingerprint={enable_fingerprint}"
        )

        # 1. Build search tokens from the organisation's own domains
        tokens = generate_tokens(org_domains, include_impersonation=detect_impersonation)
        Actor.log.info(f"Generated {len(tokens)} CT search tokens")

        # 2. Optional Apify Proxy
        proxy_url = None
        if use_proxy:
            cfg = await Actor.create_proxy_configuration(groups=["RESIDENTIAL"])
            if cfg:
                proxy_url = await cfg.new_url()

        # 3. Discover the estate from Certificate Transparency
        records, failed = await query_all_tokens(tokens, proxy_url=proxy_url)
        ct_complete = not failed
        Actor.log.info(f"CT returned {len(records)} certificate records ({len(failed)} tokens failed)")
        if failed:
            # Absence-based findings are suppressed downstream when this is set,
            # so the run degrades honestly instead of inventing "no valid cert".
            Actor.log.warning(
                f"Incomplete CT sweep, tokens failed: {failed}. Findings that depend on "
                f"seeing an asset's full certificate history are suppressed this run."
            )

        # 4. Classify and score into own-asset risk, cert anomaly, impersonation
        findings, stats = assess(records, org_domains, min_score, ct_complete=ct_complete)
        Actor.log.info(f"{len(findings)} findings | stats={stats}")

        # 5. Optional passive fingerprint, own assets only
        if enable_fingerprint:
            own_findings = [f for f in findings if is_own_asset(f["domain"], org_domains)]
            Actor.log.info(f"Fingerprinting {len(own_findings)} owned assets (passive, single GET each)")
            for f in own_findings:
                fp = await fingerprint_asset(f["domain"])
                if fp:
                    f["fingerprint"] = fp
                    if fp.get("cve_awareness"):
                        f["reasons"].append(
                            "Technology fingerprint matched a known CVE, see fingerprint.cve_awareness"
                        )

        # 6. Diff against previous runs
        store = await Actor.open_key_value_store(name=STATE_STORE_NAME)
        seen = await load_seen(store)
        new_findings = [f for f in findings if fingerprint_key(f) not in seen]
        for f in new_findings:
            seen.add(fingerprint_key(f))
        await save_seen(store, seen)
        Actor.log.info(f"{len(new_findings)} new findings since last run")

        # 7. Push to dataset
        if new_findings:
            await Actor.push_data(new_findings)

        # 8. Alert
        alertable = [f for f in new_findings if f["severity"] in alert_severities]
        if webhook_url and alertable:
            ok = await deliver_webhook(webhook_url, {
                "source": "sentinelng",
                "organization": org_domains[0],
                "run_at": datetime.now(timezone.utc).isoformat(),
                "alert_count": len(alertable),
                "findings": alertable,
            })
            Actor.log.info(f"Webhook {'delivered' if ok else 'failed'} for {len(alertable)} alerts")

        # 9. Run summary
        summary = {
            "organization": org_domains[0],
            "run_at": datetime.now(timezone.utc).isoformat(),
            "tokens": len(tokens),
            "tokens_failed": len(failed),
            "records_examined": len(records),
            "ct_complete": ct_complete,
            "findings": len(findings),
            "new_findings": len(new_findings),
            "stats": stats,
            "by_type": {
                t: sum(1 for f in new_findings if f["finding_type"] == t)
                for t in ("own_asset_risk", "cert_anomaly", "impersonation")
            },
            "by_severity": {
                s: sum(1 for f in new_findings if f["severity"] == s)
                for s in ("critical", "high", "medium", "low")
            },
        }
        await Actor.set_value("RUN_SUMMARY", summary)
        Actor.log.info(f"Run summary: {summary}")


if __name__ == "__main__":
    asyncio.run(main())
