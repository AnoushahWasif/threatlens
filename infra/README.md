# infra

Terraform for the AWS deployment. **Nothing here has been applied yet.** Creating anything in AWS waits for an explicit go-ahead, and CI has no AWS credentials: it only checks the code.

## What's here (days 15 and 16)

```
main.tf            the HTTP API itself, the four modules, the queue policy, a budget alarm
modules/data       one KMS key; DynamoDB table; uploads bucket; scan queue + dead-letter
                   queue; the LLM key's secret (empty: its value is put in by hand)
modules/web        private S3 bucket + CloudFront (site and /api on one origin)
modules/auth       Cognito user pool (admin-created accounts only), hosted UI, web client
modules/api        API and worker Lambdas, each with its own role; JWT authorizer, routes,
                   stage throttling; the worker's SQS trigger
functions/         the two CloudFront Functions, with node:test tests
scripts/           csp-hashes.mjs: script hashes from the web export, for the CSP
```

Who may do what (each role's policy names single resources, and KMS use is limited to the service it comes through):

| | Table | `uploads/` | `findings/` | Queue | LLM secret |
|-|-------|-----------|------------|-------|------------|
| API | Get, Put, Update, Query | put | get | send (and the queue policy refuses everyone else) | get |
| Worker | Get, Update | get | put | receive, delete | none |

No one gets Scan, DeleteItem or table admin. Uploads expire after 7 days, and old versions of findings files after 30.

One origin for everything: CloudFront serves the static site and sends `/api/*` to API Gateway (a function strips the `/api`). The browser never makes a cross-origin call, so the API has no CORS at all, and the CSP's `connect-src` is just `'self'` (plus the Cognito domain for the token exchange).

## Checks (all offline)

| Check | Where |
|-------|-------|
| `terraform fmt -check`, `init -backend=false`, `validate` | CI `infra` job, and locally |
| tflint with the AWS ruleset (0.49.0) | CI |
| Trivy misconfiguration scan; accepted findings with reasons in `.trivyignore.yaml`, some with an expiry date | CI, and locally |
| CloudFront Functions: unit tests, plus every page and prefetch file of a real export | `node --test "infra/**/*.test.mjs"` |
| Lambda zip built from the lockfile and run in AWS's `public.ecr.aws/lambda/python:3.12` image | CI `lambda-package` job |

A browser run against a local stand-in for the distribution (the same functions, the same CSP from a fresh build's hashes, `/api` proxied to the real API) signed in, loaded projects, created a threat model and prefetched three pages with 0 CSP violations and 0 404s.

## Deploy order (day 17)

The web build bakes in the Cognito client id and domain (outputs of the apply), and the CSP hashes come from the build (an input of the apply). So a deploy applies twice:

1. `uv run python scripts/package_lambda.py`, then `terraform apply` (with the last build's hashes; on the very first run, any build's)
2. `pnpm build` with the `web_build_env` output as environment
3. `node infra/scripts/csp-hashes.mjs apps/web/out > infra/web.auto.tfvars.json`, then `terraform apply` again: only the CSP changes
4. sync `apps/web/out` to the bucket, then invalidate CloudFront

The LLM key is never in Terraform or its state: put it in once with `aws secretsmanager put-secret-value --secret-id <llm_secret_arn output>`, then set `THREATLENS_LLM_PROVIDER=anthropic` in `api_environment`. Accounts are created with `aws cognito-idp admin-create-user`.

Until then: pages cached from the previous build can briefly meet the new CSP. A page whose hashes don't match loses its inline scripts until it reloads.

## Not yet

- **WAF:** not included, because it costs about $5–10 a month and needs approval.
- **Custom domain:** with no domain, CloudFront uses its default certificate, so its TLS minimum can't be raised.
- **The API's own URL:** it's also reachable at its execute-api address, outside CloudFront. That path still needs a valid token, but it skips the CloudFront headers.
