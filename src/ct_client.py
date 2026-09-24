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
RETRYABLE_STATUS = {429, 502, 503, 504}


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


def extract_domains(entry: dict[str, Any]) -> dict[str, bool]:
    """
    Pull every hostname from a crt.sh entry, keeping its wildcard flag.

    Returns {hostname: is_wildcard}.

    crt.sh puts SANs in name_value (newline separated) and the primary name in
    common_name. Both must be read: sometimes the organisation name lands in
    name_value and the real hostname is only in common_name. Reading name_value
    alone was a real bug that made 394 certificates look like 1 domain.

    The wildcard flag has to be captured HERE, because the next thing this
    function does is strip the "*." prefix, and after that the fact is gone.
    That loss was real: the estate sweep was fetching wildcard certificates
    and silently discarding the most useful thing about them, which is how
    much of the estate a single stolen key would cover.
    """
    names: dict[str, bool] = {}
    for field in ("name_value", "common_name"):
        raw = entry.get(field) or ""
        for line in raw.split("\n"):
            candidate = line.strip().lower()
            wildcard = candidate.startswith("*.")
            host = candidate.lstrip("*.")
            if host and " " not in host and "." in host:
                # One certificate routinely lists both example.com and
                # *.example.com, and both reduce to the same host here. OR
                # the flag so the wildcard survives pairing with a plain name.
                names[host] = names.get(host, False) or wildcard
    return names


async def query_token(client: httpx.AsyncClient, token: str) -> list[dict[str, Any]]:
    """
    Query CT logs for certificates matching `token`.

    A token that already carries its own wildcard (the '%.example.com' estate
    pattern) is sent verbatim, because that is crt.sh's indexed subdomain form
    and wrapping it again would turn it into a slow, truncated LIKE scan. A
    bare brand root is wrapped into '%root%' for lookalike discovery.
    """
    query = token if token.startswith("%") else f"%{token}%"
    params = {"q": query, "output": "json"}

    entries: list[dict[str, Any]] = []
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = await client.get(CRTSH_URL, params=params, timeout=REQUEST_TIMEOUT)
            if response.status_code in RETRYABLE_STATUS:
                # 429 is rate limiting and clears on its own. 502/503/504 mean
                # crt.sh's backend gave up on the query, which broad substring
                # searches routinely cause, so back off rather than hammer it.
                await asyncio.sleep(RETRY_BACKOFF_SECONDS * attempt)
                continue
            response.raise_for_status()
            raw = response.text.strip()
            if not raw:
                entries = []
                break
            if not raw.startswith(("[", "{")):
                # crt.sh answers overload with an HTML error page under a 200 as
                # well as under a 5xx. Treat it as a failed query, not as zero
                # certificates: "no results" and "no answer" mean opposite things
                # to a scorer reasoning about absence.
                raise CTQueryError(
                    f"CT query for token '{token}' returned non-JSON "
                    f"(status {response.status_code}, starts {raw[:40]!r})"
                )
            entries = json.loads(raw)
            break
        except CTQueryError:
            if attempt == MAX_RETRIES:
                raise
            await asyncio.sleep(RETRY_BACKOFF_SECONDS * attempt)
        except Exception as exc:  # noqa: BLE001
            if attempt == MAX_RETRIES:
                raise CTQueryError(f"CT query failed for token '{token}': {exc}") from exc
            await asyncio.sleep(RETRY_BACKOFF_SECONDS * attempt)

    records: list[dict[str, Any]] = []
    for entry in entries:
        issuer = entry.get("issuer_name", "unknown")
        for host, is_wildcard in extract_domains(entry).items():
            records.append({
                "domain": host,
                "is_wildcard": is_wildcard,
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
