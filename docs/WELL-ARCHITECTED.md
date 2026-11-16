# Well-Architected review

A review of ThreatLens against the six pillars of the AWS Well-Architected Framework, written on 17 Nov 2026.

**Nothing has been deployed yet.** This reviews the Terraform in `infra/` and the app as written, not a running system, and every cost figure below is an estimate from list prices. Where something is planned but not built, it says so.

## Summary

| Pillar | Where it stands | Biggest gap |
|--------|-----------------|-------------|
| Operational excellence | Everything in Terraform, JSON logs with request ids, 8 alarms, a dashboard, one end-to-end test | No deploy pipeline yet (day 17), no runbook for the alarms |
| Security | Two token checks, one IAM role per function naming single resources, one KMS key, private buckets, admin-created accounts, scans in CI | No WAF; the API is also reachable outside CloudFront |
| Reliability | Queue with retries and a dead-letter queue, idempotent worker, optimistic locking, partial scans marked as such | One region, and point-in-time recovery has never been restored from |
| Performance efficiency | Serverless sized to the work, static site on a CDN, bulk OSV calls with caching | Cold starts not measured; the API can only use 20 requests a second |
| Cost optimization | About $1.40 a month idle, budget alarm on actual and forecast spend | X-Ray's default sampling traces almost every request at low traffic |
| Sustainability | Nothing runs when nobody uses it; uploads expire after 7 days | x86_64 instead of Graviton; findings files are kept forever |

## Operational excellence

**In place**
- All infrastructure is Terraform, checked in CI with `fmt`, `validate`, tflint and Trivy (decision 53 and `infra/README.md`). No console clicking.
- One JSON object per log line, with a request id the server chooses and carries from the API through the queue into the worker, so one upload can be followed end to end (decision 73).
- Eight alarms and one dashboard in `infra/modules/monitoring`, emailed through an encrypted SNS topic (decision 74). They cover API 5xx and p95 latency, errors per function, anything in the dead-letter queue, scans stuck in the queue, unhandled exceptions and repeated scan failures.
- One Playwright journey runs the built site through the real CloudFront function code against the real API (decision 75).

**Gaps**
- **No deploy pipeline.** Day 17 (GitHub Actions to AWS with OIDC) waits on the AWS account details. Until then, a deploy is the manual two-apply sequence in `infra/README.md`.
- **No runbook.** An alarm email says what fired but not what to do. Each alarm needs a short "check this first" note.
- **No canary.** A deploy goes straight to all traffic. At this size, a smoke test against `/health` and one scan after each deploy is enough. Lambda aliases with weighted traffic would be the next step.
- **Alarms only go to email.** That's fine for one person, but nobody is on call.

## Security

**In place**
- **Identity:** Cognito with admin-created accounts only, 12-character passwords, optional TOTP and code + PKCE (decision 59). API Gateway checks the JWT, and then the API checks it again itself (decisions 26 and 54).
- **Least privilege:** one IAM role per Lambda, each naming single resources. Nobody gets `Scan`, `DeleteItem` or table admin. KMS use is limited to the service it comes through, and only the API may put messages on the queue (decisions 56 and 57).
- **Data:**
  - One customer-managed KMS key, rotated yearly, for the table, bucket, queues, secret, Lambda environment and logs. The bucket refuses writes made with any other key (decision 58).
  - HTTPS is required everywhere, and public access is blocked on both buckets.
  - Uploads are deleted after 7 days.
- **Isolation between users:** the partition key is the caller's `sub` from a verified token, so a request can't name another user's item.
- **Secrets:** the LLM key is put into Secrets Manager by hand, so it's never in the repo, the Terraform state or an environment variable (decision 60).
- **Browser:** a strict CSP built from the hashes of the real export, with no `unsafe-inline`, plus the other security headers from CloudFront (decision 51).
- **Supply chain:** Gitleaks, Semgrep, Trivy, an SBOM of ThreatLens itself, Dependabot, and actions pinned by commit hash (day 18).

**Gaps**
- **No WAF.** It would add rate-based blocking per IP before requests reach API Gateway. It costs about $5 a month plus $1 per rule, so it waits for approval. The stage throttle (20 requests a second) and the per-user limits in the app cover part of it.
- **The API's own execute-api URL works around CloudFront.** The token checks still apply there, but a WAF on CloudFront wouldn't. The fix is a secret header added by CloudFront and checked at the API, or a Lambda authorizer that checks it.
- **No custom domain**, so CloudFront uses its default certificate and its minimum TLS version can't be raised.
- **No CloudTrail or GuardDuty set up in this project.** They belong to the account rather than the app, and should be on before day 17.
- **No access logs for CloudFront or the buckets yet.** The Trivy exceptions for them expire on 15 Dec 2026.

## Reliability

**In place**
- **Scans go through SQS:**
  - The worker assumes a message can arrive more than once: claiming a scan is a versioned save that only one worker wins, and finished scans are skipped (decision 43).
  - It makes three attempts, then marks the scan failed.
  - A crash it never sees goes to the dead-letter queue after 5 receives, and that queue has an alarm.
- **Simultaneous edits:** a save that lost a race to another one is applied again, up to 3 times, then answered with a 409 (decision 33).
- **Outside services failing:** if OSV, EPSS or KEV are down, the scan finishes as "partial" and the web app says so, rather than reporting no findings (decisions 8, 11 and 12).
- **Storage limits:** DynamoDB throttling returns a 503 with `Retry-After` (decision 38).
- **Recovery:**
  - The table has point-in-time recovery and deletion protection.
  - The upload bucket is versioned.
  - The Cognito pool has deletion protection.

**Gaps**
- **One region (eu-west-2).** If the region goes down, so does ThreatLens. For a portfolio tool that's an accepted risk, and a second region would roughly double the fixed cost. The recovery plan is to re-apply the Terraform elsewhere, but the table and user pool would be lost unless backups are copied to another region.
- **Restore never tested.** Point-in-time recovery restores into a new table, and the API reads its table name from the environment. The steps should be written down and tried once.
- **No backup of findings files outside the bucket.** Versioning protects against overwrites, not against losing the bucket.

## Performance efficiency

**In place**
- **The site:** static pages on CloudFront, with no server to warm up.
- **The API:** Lambda behind an HTTP API, with 512 MB and a 29 s timeout.
- **The scan worker:**
  - It has 1 GB and runs at most 2 scans at a time. That limit protects the outside services rather than our own capacity (decision 61).
  - On a real 4-line file, the upload answered in 0.22 s and the scan took 22 s (decision 41).
  - OSV is queried 1000 packages at a time and its answers are cached. EPSS is queried 100 CVEs at a time, and KEV is downloaded once a day.
- **Large data:** findings live in one S3 file per scan, not in DynamoDB items, so a 20,000-package scan is one write (decision 40).

**Gaps**
- **Cold starts not measured.** The zip is 28 MB, or 60 MB unzipped. Python with FastAPI usually starts in about 1 to 2 seconds, but that needs measuring once it's deployed. Provisioned concurrency would fix it but costs money while idle.
- **Throttle of 20 requests a second, burst 40.** It's set low on purpose (cost and fairness), but the web app polls a running scan every 2 s, so about 40 people waiting on scans at the same moment would use all of it. Raise the throttle once real traffic has been seen.
- **Memory sizes not tuned.** The 512 MB and 1 GB were chosen without data. AWS Lambda Power Tuning on a real scan would set them properly.

## Cost optimization

Prices are AWS list prices as of November 2026. Where a price differs by region, the table uses the us-east-1 figure. London (eu-west-2) is usually a few percent higher, which at these volumes is cents. Check them in the AWS Pricing Calculator before approving a deploy.

### Fixed monthly cost (charged even when nobody uses it)

| Item | Cost | Note |
|------|------|------|
| KMS customer-managed key | $1.00 | Prorated by the hour |
| Secrets Manager secret | $0.40 | The LLM key |
| Everything else | $0 | Lambda, API Gateway, DynamoDB on-demand, SQS, CloudFront and S3 charge only for use |
| **Idle total** | **about $1.40** | |

### Three levels of use

The assumptions are listed so they can be checked:

- **A scan:** 22 s at 1 GB in the worker (decision 41), about 4 table writes, and one 200 KB findings file.
- **An API request:** 0.2 s at 512 MB in the API Lambda.

| | Idle (demo only) | Light | Heavier |
|-|------------------|-------|---------|
| Users a month | 0 to 2 | 20 | 1,000 |
| API requests a month | under 1,000 | 30,000 | 1,000,000 |
| Scans a month | under 10 | 300 | 10,000 |
| Fixed (KMS key, secret) | $1.40 | $1.40 | $1.40 |
| API Gateway HTTP API ($1.00 per million) | $0 | $0.03 | $1.00 |
| Lambda (1M requests and 400,000 GB-s free every month) | $0 | $0 | $0 (about 320,000 GB-s) |
| DynamoDB on-demand (25 GB storage free) | $0 | $0.01 | about $0.60 |
| Point-in-time recovery ($0.20 per GB-month) | $0 | $0 | under $0.20 |
| S3 (findings files and requests) | $0 | $0.01 | about $0.15 |
| KMS requests ($0.03 per 10,000) | $0 | $0.01 | about $0.30 |
| CloudFront (1 TB and 10M requests free every month) | $0 | $0 | $0 |
| CloudWatch (8 of 10 free alarms, 1 of 3 free dashboards, 4 of 10 free metrics, under 5 GB of logs free) | $0 | $0 | $0 |
| X-Ray (100,000 traces free) | $0 | $0 | about $3 with default sampling, under $0.50 with a sampling rule |
| Cognito (10,000 monthly users free) | $0 | $0 | $0 |
| SQS, SNS email, Budgets | $0 | $0 | $0 |
| **Total** | **about $1.40** | **about $1.50** | **about $6.50, or about $4 with an X-Ray sampling rule** |

All three levels stay under the $10 budget alarm (decision 55). On an AWS account opened after 15 July 2025, the sign-up credits would cover these amounts for the first months.

**Not included:**
- **The LLM.** Drafting is billed by Anthropic, not AWS. It's off until a key and `THREATLENS_LLM_PROVIDER` are set, it's capped at 20 drafts an hour (decision 22), and the key should have a spend limit at the provider. That cap allows up to 14,400 drafts a month, so the provider limit is what really bounds this bill.
- **WAF** (about $5 to $10 a month) and a custom domain (about $1 a month for a Route 53 zone, plus the domain).
- **Data transfer above the free tier.** Lockfiles and findings files are small.

### Findings

- **X-Ray sampling.** Both Lambdas have active tracing with AWS's default rule: the first request in each second, then 5% of the rest. At low, steady traffic almost every request is first in its second, so nearly all of them get traced. At a million requests a month that's several hundred thousand traces, against 100,000 free. A sampling rule with a smaller reservoir, or tracing on the worker only, fixes it. That's a small Terraform change, kept out of this review.
- **Cognito tier.** The pool doesn't set `user_pool_tier`, so it gets AWS's default (Essentials). That's free up to 10,000 monthly users either way, but ThreatLens seems to use nothing Lite lacks (it uses the classic hosted UI and optional TOTP), and Lite is cheaper past the free tier. Confirm the feature list before switching. Setting it explicitly also stops the default from changing under it.
- **Graviton.** arm64 Lambda is about 20% cheaper per GB-second. The functions are x86_64 so CI can run the real Lambda image (decision 53). It's worth switching once CI can run an arm64 image, though at these volumes the saving is cents.

## Sustainability

**In place**
- **Nothing runs while nobody uses it:** no servers, containers or provisioned capacity.
- **Data is kept only as long as needed:**
  - Uploads are deleted after 7 days, and old versions of findings files after 30 days.
  - Logs are kept for 30 days.
  - Dead-letter messages are kept for 14 days.
- **Requests to outside services are cut down:** answers are cached, OSV is called in batches, and KEV is downloaded once a day rather than per scan.

**Gaps**
- **x86_64, not Graviton** (see the cost findings above). arm64 uses less energy for the same work.
- **Findings files are kept forever.** The web app only shows each project's newest scan, so older scans' findings could expire after, say, 90 days. That's a product decision rather than a technical one.

## What to do next, in order

1. **Before the first deploy (day 17):**
   - CloudTrail and GuardDuty on the account.
   - An X-Ray sampling rule.
   - `user_pool_tier` set explicitly.
   - A one-page runbook for the 8 alarms.
2. **After the first deploy:**
   - Measure cold starts and tune memory with real scans.
   - Try a point-in-time restore once and write the steps down.
3. **Before 15 Dec 2026:** access logs for CloudFront and both buckets (the Trivy exceptions expire).
4. **When there's a reason to pay for it:**
   - WAF on CloudFront, with the API locked to CloudFront.
   - A custom domain with TLS 1.2 minimum.
