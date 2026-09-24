"""
Seed the local dataset with demo findings so the dashboard shows all four
severity bands.

Why this exists: a real run against a real bank produces no critical findings.
That is the honest result, and it is also a poor demo, because the dashboard's
critical tile reads zero and the severity meter only ever shows three bands.
This script supplies a fictional estate that exercises every band and all three
finding types.

Two rules it follows:

1. It does not touch detection logic, and it does not hand-write scores. It
   builds certificate records in exactly the shape `ct_client` produces, then
   runs them through the real `assess()`. Every score, severity and reason
   string you see is what the live engine computes. If the scoring changes, the
   seed output changes with it, so this cannot drift into a pretty lie.

2. Every item carries `"demo_seed": true`. Seeded findings must never be
   mistaken for real ones, in a demo or afterwards.

Certificate ages are relative to the moment you run it, so the "issued in the
last 72 hours" signals stay true however long from now the demo happens.

Usage:
    python scripts/seed_demo.py              append to the existing dataset
    python scripts/seed_demo.py --replace    clear the dataset first
    python scripts/seed_demo.py --dry-run    print the findings, write nothing
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from src.scoring import assess  # noqa: E402

DEFAULT_DATASET = REPO_ROOT / "storage" / "datasets" / "default"

# A fictional bank. Deliberately not a real institution, and deliberately not
# hyphenated: a hyphen in the brand would trip the label splitter and muddy
# which signal earned which score.
DEMO_ORG = "demobank.ng"

DIGICERT = "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1"
LETSENCRYPT = "C=US, O=Let's Encrypt, CN=R11"

CT_TIME = "%Y-%m-%dT%H:%M:%S"
HOURS_PER_DAY = 24

_counter = [0]


def _record(host, issuer=DIGICERT, valid_days=365, age_hours=720, wildcard=False):
    """One certificate record, shaped exactly as ct_client.query_token emits."""
    _counter[0] += 1
    not_before = datetime.now(timezone.utc) - timedelta(hours=age_hours)
    return {
        "domain": host,
        "is_wildcard": wildcard,
        "matched_token": "%." + DEMO_ORG,
        "issuer": issuer,
        "crtsh_id": 9_000_000_000 + _counter[0],
        "not_before": not_before.strftime(CT_TIME),
        "not_after": (not_before + timedelta(days=valid_days)).strftime(CT_TIME),
        "entry_timestamp": None,
        "serial_number": None,
    }


def demo_records():
    """
    The fictional estate.

    Each entry is chosen so the real scorer lands it in a specific band. The
    comments record the intent; the engine decides the number.
    """
    day = HOURS_PER_DAY
    return [
        # CRITICAL. The Sterling Bank shape: a forgotten internal pilot server,
        # freshly certified, holding a wildcard key that covers everything
        # beneath it. pilot + internal labels, recent cert, wildcard.
        _record("enf-pilot.internal.demobank.ng", valid_days=90, age_hours=11, wildcard=True),

        # HIGH. A staging box on a wildcard certificate.
        _record("staging.demobank.ng", valid_days=365, age_hours=200 * day, wildcard=True),

        # HIGH. The GTBank shape: an authentication host with years of DigiCert
        # history suddenly answering to a certificate issued hours ago.
        _record("login.demobank.ng", issuer=DIGICERT, valid_days=365, age_hours=400 * day),
        _record("login.demobank.ng", issuer=LETSENCRYPT, valid_days=89, age_hours=9),

        # MEDIUM. Ordinary non-production hosts, nothing recent about them.
        _record("uat.demobank.ng", valid_days=365, age_hours=300 * day),
        # Also lapsed: its newest certificate expired inside the last year.
        _record("legacy.demobank.ng", valid_days=365, age_hours=420 * day),

        # LOW. An auxiliary service worth inventorying but not alarming about.
        _record("webmail.demobank.ng", valid_days=365, age_hours=150 * day),

        # LOW. The false positive class that item 1 defused: a marketing host
        # that migrated to a free CA years ago. Present so the demo shows the
        # tool declining to cry wolf.
        _record("campaign.demobank.ng", issuer=DIGICERT, valid_days=365, age_hours=1500 * day),
        _record("campaign.demobank.ng", issuer=LETSENCRYPT, valid_days=89, age_hours=1000 * day),

        # HIGH. A lookalike the organisation does not own, on a risky TLD.
        _record("demobank-secure.top", issuer=DIGICERT, valid_days=365, age_hours=60 * day),
    ]


def build_findings():
    """Score the fictional estate with the real engine and mark every item."""
    findings, _stats = assess(demo_records(), [DEMO_ORG], min_score=20)
    for finding in findings:
        finding["demo_seed"] = True
        finding["organization"] = DEMO_ORG
    return findings


def next_index(dataset_dir):
    """Highest existing item number, so appending does not overwrite a real run."""
    highest = 0
    for path in dataset_dir.glob("*.json"):
        if path.stem.isdigit():
            highest = max(highest, int(path.stem))
    return highest + 1


def write_dataset(findings, dataset_dir, replace):
    if replace and dataset_dir.exists():
        shutil.rmtree(dataset_dir)
    dataset_dir.mkdir(parents=True, exist_ok=True)

    start = next_index(dataset_dir)
    for offset, finding in enumerate(findings):
        path = dataset_dir / f"{start + offset:09d}.json"
        path.write_text(json.dumps(finding, indent=2), encoding="utf-8")

    total = sum(1 for p in dataset_dir.glob("*.json") if p.stem.isdigit())
    now = datetime.now(timezone.utc)
    meta_path = dataset_dir / "__metadata__.json"
    meta = {"id": "default", "name": None, "item_count": total}
    if meta_path.exists():
        try:
            meta = {**json.loads(meta_path.read_text(encoding="utf-8")), "item_count": total}
        except (OSError, ValueError):
            pass
    meta.setdefault("created_at", str(now))
    meta["accessed_at"] = str(now)
    meta["modified_at"] = str(now)
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return start, total


def main():
    parser = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    parser.add_argument("--replace", action="store_true",
                        help="clear the dataset before seeding")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the findings without writing anything")
    parser.add_argument("--dir", type=Path, default=DEFAULT_DATASET,
                        help=f"dataset directory (default: {DEFAULT_DATASET})")
    args = parser.parse_args()

    findings = build_findings()
    by_severity = Counter(f["severity"] for f in findings)
    by_type = Counter(f["finding_type"] for f in findings)

    print(f"Demo estate: {DEMO_ORG}   ({len(findings)} findings, all marked demo_seed)")
    print()
    for f in sorted(findings, key=lambda v: -v["risk_score"]):
        print(f"  {f['risk_score']:3}  {f['severity']:8}  {f['finding_type']:15}  {f['domain']}")
    print()
    print("  by severity:", dict(by_severity))
    print("  by type    :", dict(by_type))

    missing = {"critical", "high", "medium", "low"} - set(by_severity)
    if missing:
        print()
        print(f"  WARNING: no findings in {sorted(missing)}. The dashboard will show")
        print("  an empty band. Scoring may have changed since this seed was written.")

    if args.dry_run:
        print()
        print("  dry run, nothing written")
        return

    start, total = write_dataset(findings, args.dir, args.replace)
    print()
    print(f"  wrote items {start:09d} to {start + len(findings) - 1:09d} in {args.dir}")
    print(f"  dataset now holds {total} items")


if __name__ == "__main__":
    main()
