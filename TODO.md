# TODO: Apify team feedback (post-hackathon)

- [x] **README.** Key sentence at the top, written for buyers rather than the hackathon. Repository layout removed. Niche widened to all fintech, banks and organisations holding sensitive data. Technical detail moved to READMORE.md.

## Pricing and monetisation
- [ ] Stop charging per vulnerability or finding.
- [ ] Charge one event per run, priced on the value of the check, not on the number of results.
- [ ] Reposition pricing and the Store listing for B2B.

## Reporting and delivery
- [ ] Send a summary email to a configurable list of stakeholders after every run.
- [ ] Give every run a shareable report link that stakeholders can open without a dataset ID or API token, and update it each run so they can make informed decisions.
- [ ] Present alerts as an actionable checklist (for example "☐ Confirm `staging.x.com` is still needed"), not prose.
- [ ] Extend webhook integrations: native Slack formatting (Block Kit), Teams and others.

## Configuration
- [ ] Let users set the run schedule (daily, weekly or monthly) from the input.
- [ ] Rework the `min_score` decision: make the threshold fully open and user-defined, with clearer guidance in place of a fixed default.

## Infrastructure
- [ ] Use Apify Proxy by default on every run so CT queries behave consistently (currently opt-in via `use_apify_proxy`).

Once these ship, update the README "What you get on every run" section to mention the email, report link and checklist.
