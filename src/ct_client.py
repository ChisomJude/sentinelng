"""
Certificate Transparency log client.

Reads crt.sh, which aggregates the Chrome and Apple trusted CT logs and exposes
a JSON endpoint. Every publicly trusted certificate is logged here within
minutes of issuance, so this is a complete view of an organisation's certified
estate, not a sample.

This is the discovery layer for the whole tool. Everything downstream, asset
inventory, certificate anomalies, impersonation, works from what this returns.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any

import httpx

CRTSH_URL = "https://crt.sh/"
REQUEST_TIMEOUT = 60.0
MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 4


class CTQueryError(RuntimeError):
    """Raised when a CT log query fails after all retries."""


def parse_ct_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def extract_domains(entry: dict[str, Any]) -> set[str]:
    """
    Pull every hostname from a crt.sh entry.

    crt.sh puts SANs in name_value (newline separated) and the primary name in
    common_name. Both must be read: sometimes the organisation name lands in
    name_value and the real hostname is only in common_name. Reading name_value
    alone was a real bug that made 394 certificates look like 1 domain.
    """
    names: set[str] = set()
    for field in ("name_value", "common_name"):
        raw = entry.get(field) or ""
        for line in raw.split("\n"):
            host = line.strip().lower().lstrip("*.")
            if host and " " not in host and "." in host:
                names.add(host)
    return names


async def query_token(client: httpx.AsyncClient, token: str) -> list[dict[str, Any]]:
    """Query CT logs for every certificate whose subject contains `token`."""
    params = {"q": f"%{token}%", "output": "json"}

    entries: list[dict[str, Any]] = []
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = await client.get(CRTSH_URL, params=params, timeout=REQUEST_TIMEOUT)
            if response.status_code == 429:
                await asyncio.sleep(RETRY_BACKOFF_SECONDS * attempt)
                continue
            response.raise_for_status()
            raw = response.text.strip()
            entries = json.loads(raw) if raw else []
            break
        except Exception as exc:  # noqa: BLE001
            if attempt == MAX_RETRIES:
                raise CTQueryError(f"CT query failed for token '{token}': {exc}") from exc
            await asyncio.sleep(RETRY_BACKOFF_SECONDS * attempt)

    records: list[dict[str, Any]] = []
    for entry in entries:
        issuer = entry.get("issuer_name", "unknown")
        for host in extract_domains(entry):
            records.append({
                "domain": host,
                "matched_token": token,
                "issuer": issuer,
                "crtsh_id": entry.get("id"),
                "not_before": entry.get("not_before"),
                "not_after": entry.get("not_after"),
                "entry_timestamp": entry.get("entry_timestamp"),
                "serial_number": entry.get("serial_number"),
            })
    return records


async def query_all_tokens(
    tokens: list[str],
    concurrency: int = 4,
    proxy_url: str | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """
    Query every token with bounded concurrency, deduplicated by (domain, cert).
    Returns (records, failed_tokens) so one bad token never kills the run.
    """
    semaphore = asyncio.Semaphore(concurrency)
    records: list[dict[str, Any]] = []
    failed: list[str] = []

    client_kwargs: dict[str, Any] = {
        "headers": {"User-Agent": "SentinelNG/1.0 (external attack surface monitor)"},
        "follow_redirects": True,
    }
    if proxy_url:
        client_kwargs["proxy"] = proxy_url

    async with httpx.AsyncClient(**client_kwargs) as client:

        async def run(token: str) -> None:
            async with semaphore:
                try:
                    records.extend(await query_token(client, token))
                except CTQueryError:
                    failed.append(token)

        await asyncio.gather(*(run(t) for t in tokens))

    deduped: dict[tuple[str, Any], dict[str, Any]] = {}
    for record in records:
        deduped.setdefault((record["domain"], record["crtsh_id"]), record)

    return list(deduped.values()), failed
