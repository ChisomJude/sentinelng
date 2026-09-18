# Deployment

Order matters. Each step depends on the one before it.

## 1. Local verification

```bash
git clone https://github.com/<your-username>/sentinelng.git
cd sentinelng

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install pytest ruff

ruff check src tests
pytest tests -v
```

18 tests should pass in under a second. They run offline.

## 2. First live run

```bash
npm install -g apify-cli
apify login

apify run --input '{
  "organization_domains": ["sterling.ng"],
  "min_score": 20,
  "detect_impersonation": true
}'
```

Results land in `storage/datasets/default/`. A 720 hour lookback sweeps the last
30 days and gives you the baseline you need for allowlist tuning.

Expect noise on this first run. That is the point of it.

## 3. Deploy the Actor

```bash
apify push
```

The Actor appears in Apify Console. Run it once from the Console to confirm the
input form renders correctly from the schema.

## 4. Schedule it

Apify Console, Schedules, Create new.

| Cadence | Set `lookback_hours` to |
|---|---|
| Hourly | 2 |
| Every 6 hours | 8 |
| Daily | 26 |

Always set the lookback longer than the interval. The overlap means nothing
falls between runs, and the key-value store prevents duplicate alerts.

## 5. Deploy the dashboard

```bash
npm install -g vercel
cd dashboard
vercel link          # creates .vercel/project.json
vercel deploy --prod
```

`vercel.app` default URL is fine to start. For a custom subdomain:

```
Vercel dashboard, Project, Settings, Domains
Add: sentinelng.<your-domain>
```

Vercel gives you the CNAME target. Add it at your DNS provider. TLS is issued
automatically, usually within a minute.

## 6. Wire up CI/CD

Read `.vercel/project.json` from step 5 for the org and project IDs.

Repository, Settings, Secrets and variables, Actions, New repository secret:

| Secret | Source |
|---|---|
| `APIFY_TOKEN` | Apify Console, Settings, Integrations |
| `VERCEL_TOKEN` | Vercel, Account Settings, Tokens |
| `VERCEL_ORG_ID` | `.vercel/project.json`, field `orgId` |
| `VERCEL_PROJECT_ID` | `.vercel/project.json`, field `projectId` |

Push to `main`. The Deploy workflow runs tests, then ships the Actor and the
dashboard. Both deploy steps skip cleanly if their secret is missing.

## 7. Connect alerting

Create a Slack incoming webhook, then set `webhook_url` on the scheduled run.
It is marked secret in the input schema, so it is not written to logs or to the
run record.

Verify by running once with `min_score` at 0. Something will fire. Set it back
to 35 afterwards.

## Checklist

- [ ] Tests pass locally
- [ ] 30 day sweep run and reviewed
- [ ] Every legitimate domain added to `official_domains`
- [ ] Actor pushed and running from Console
- [ ] Schedule created with correct lookback
- [ ] Dashboard deployed and loading findings
- [ ] Custom subdomain resolving with TLS
- [ ] All four secrets set, Deploy workflow green
- [ ] Webhook verified end to end
