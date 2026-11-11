# ThreatLens

[![CI](https://github.com/AnoushahWasif/threatlens/actions/workflows/ci.yml/badge.svg)](https://github.com/AnoushahWasif/threatlens/actions/workflows/ci.yml)

> Work in progress. Started October 2026.

An application security workspace that helps a small team decide what to fix first.

Give it a project (an SBOM or lockfile, plus a short description of the architecture) and it will:

1. **Find vulnerable dependencies** using the [OSV.dev](https://osv.dev) database.
2. **Rank them by real risk**: how likely each CVE is to be exploited in the next 30 days ([FIRST EPSS](https://www.first.org/epss/)) and whether it's already being exploited ([CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)), not just its CVSS score.
3. **Draft a STRIDE threat model** from the architecture description using an LLM, which you then review, edit, accept or reject.
4. **Show it on a dashboard** with a remediation checklist grouped by secure-SDLC phase.

## Why

Most scanners return hundreds of CVEs sorted by CVSS, and most of those will never be exploited. EPSS and KEV are public, free signals that make the list much shorter. Threat modelling is the other half: it's the step teams skip because it takes a blank page and an expert. An LLM draft that a human reviews makes the blank page go away without trusting the model blindly.

## Planned stack

- **Web:** Next.js, TypeScript, Tailwind, shadcn/ui, Recharts
- **API:** Python 3.12, FastAPI, Pydantic v2
- **AWS:** S3 + CloudFront, API Gateway + Lambda, DynamoDB, SQS, Cognito, Secrets Manager, KMS. Terraform for all of it, deployed from GitHub Actions with OIDC (no stored AWS keys)
- **Security pipeline:** Gitleaks, Semgrep, Trivy, SBOM of ThreatLens itself

## Repo layout

```
apps/api/     FastAPI service and scan worker (Python, uv)
apps/web/     Next.js frontend (pnpm), from Day 7
infra/        Terraform for AWS (written and checked, not applied yet)
docs/         architecture and threat model
```

`make install`, `make lint` and `make test` run against the API. CI runs the same checks plus a Gitleaks scan of the full git history on every push.

## Threat-model drafting (API)

| Route | What it does |
|-------|--------------|
| `POST /threat-models` | Save a name and an architecture description (40–8,000 characters) |
| `POST /threat-models/{id}/draft` | Ask the LLM for STRIDE threats; they're stored with status `draft` |
| `GET /threat-models/{id}` | Read the model and its threats |
| `POST /threat-models/{id}/threats` | Add a threat by hand (stored as `accepted`) |
| `PATCH` / `DELETE /threat-models/{id}/threats/{threat_id}` | Edit, accept, reject or remove a threat |

Drafting is **off by default**, so the route answers `503 llm_disabled`. To turn it on, set `THREATLENS_LLM_PROVIDER=anthropic` and `THREATLENS_LLM_API_KEY` in `apps/api/.env`. Each draft is a paid API call, so the API allows 20 per hour (`THREATLENS_LLM_DRAFTS_PER_HOUR`). Re-drafting replaces only drafts nobody has touched.

## Sign-in

Every threat-model route needs a bearer access token, and each user sees only their own models: anyone else's reads as "not found". In production the tokens come from Amazon Cognito (hosted sign-in page, authorization code + PKCE). For local development the API runs a stand-in issuer: start it with the default `THREATLENS_AUTH_MODE=local`, open the web app, and sign in with any username. No password is checked, and the API refuses this mode when `THREATLENS_ENVIRONMENT=prod`.

Limits: 50 threat models and 5 AI drafts an hour per user, and 20 drafts an hour for the whole API. The Cognito path is unit-tested against recorded-shape responses but hasn't run against a real user pool yet. The pool is defined in Terraform (`infra/modules/auth`, not applied yet) with admin-created accounts only, so nobody can sign up on their own.

## Storage

Threat models and projects go in one DynamoDB table, keyed by user: [layout and decisions](docs/ARCHITECTURE.md#dynamodb-layout-day-13). The default for local work is an in-memory store with the same rules (lost on restart). To use DynamoDB Local instead:

```bash
docker run -p 8000:8000 amazon/dynamodb-local:3.3.1
# apps/api/.env
THREATLENS_STORE=dynamodb
THREATLENS_DYNAMODB_ENDPOINT_URL=http://localhost:8000
```

The API creates the table there on start (in AWS, Terraform will own it). Every save checks the version it read, so two edits at once can't overwrite each other. CI runs the whole API test suite a second time against DynamoDB Local. Projects have `GET/POST /projects` and `GET /projects/{id}`.

## Scans

```bash
curl -X POST "$API/projects/$PROJECT/scans?filename=requirements.txt" \
  -H "Authorization: Bearer $TOKEN" --data-binary @requirements.txt
# 202, scan "queued"; poll GET /projects/$PROJECT/scans/$SCAN, then GET /projects/$PROJECT/findings
```

The API reads the file straight away (CycloneDX JSON, `requirements.txt`, `package-lock.json`, `pnpm-lock.yaml` v6/v9, `uv.lock` or `poetry.lock`, up to 1 MB) and refuses a bad one with a 422. The network part, OSV, EPSS and KEV, runs in a worker from a queue. On a real 4-line `requirements.txt` the upload answered in 0.22 s, and the scan finished 22 s later with 24 findings. A partial scan (OSV or EPSS couldn't answer for some packages) says so in its counts instead of looking clean. Locally the worker is a thread inside the API; in AWS it will be a Lambda fed by SQS (day 15). Limits: 10 scans per user per hour.

ThreatLens scanning its own lockfiles: `uv.lock` 55 packages, 0 findings in 3.1 s; `pnpm-lock.yaml` 729 packages, 2 findings in 3.6 s (deepmerge, removed on day 18, and minimatch 10.2.6 via typescript-eslint). Direct and transitive packages are told apart for `uv.lock`, `pnpm-lock.yaml` and `package-lock.json`; `poetry.lock` doesn't record it, so everything there counts as direct. Packages from a private index (poetry `legacy` sources, uv registry URLs other than PyPI) are checked as PyPI packages: if an internal package shares a public name, it gets the public package's advisories, which is also the name an attacker would use for dependency confusion.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), which includes a threat model of ThreatLens itself.

## License

MIT
