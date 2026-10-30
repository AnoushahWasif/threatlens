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
infra/        Terraform for AWS, from Day 15
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

Drafting is **off by default**, so the route answers `503 llm_disabled`. To turn it on, set `THREATLENS_LLM_PROVIDER=anthropic` and `THREATLENS_LLM_API_KEY` in `apps/api/.env`. Each draft is a paid API call, so the API allows 20 per hour (`THREATLENS_LLM_DRAFTS_PER_HOUR`). Re-drafting replaces only drafts nobody has touched. Threat models live in memory until persistence lands (day 13), and there's no auth yet (day 12), so don't expose this API.

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), which includes a threat model of ThreatLens itself.

## License

MIT
