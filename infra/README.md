# infra

Terraform for the AWS deployment. **Nothing here has been applied yet.** Creating anything in AWS waits for an explicit go-ahead, and CI has no AWS credentials: it only checks the code.

## What's here (day 15)

```
main.tf            providers, the two modules, a monthly budget alarm
modules/web        private S3 bucket + CloudFront (site and /api on one origin)
modules/api        Lambda (FastAPI via Mangum) + HTTP API with a Cognito JWT authorizer
functions/         the two CloudFront Functions, with node:test tests
scripts/           csp-hashes.mjs: script hashes from the web export, for the CSP
```

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

The CSP hashes depend on the build, so one pipeline run does:

1. `pnpm build` with `NEXT_PUBLIC_API_URL=/api`
2. `node infra/scripts/csp-hashes.mjs apps/web/out > infra/web.auto.tfvars.json`
3. `uv run python scripts/package_lambda.py`
4. `terraform apply`
5. sync `apps/web/out` to the bucket, then invalidate CloudFront

Until then: pages cached from the previous build can briefly meet the new CSP. A page whose hashes don't match loses its inline scripts until it reloads.

## Not yet

- **The API Lambda won't start on its own yet.** Its prod settings require the DynamoDB table, SQS queue, uploads bucket, Cognito pool and the LLM key from Secrets Manager, which arrive on day 16.
- **WAF:** not included, because it costs about $5–10 a month and needs approval.
- **Custom domain:** with no domain, CloudFront uses its default certificate, so its TLS minimum can't be raised.
- **The API's own URL:** it's also reachable at its execute-api address, outside CloudFront. That path still needs a valid token, but it skips the CloudFront headers.
