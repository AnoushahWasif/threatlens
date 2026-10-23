# ThreatLens

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

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), which includes a threat model of ThreatLens itself.

## License

MIT
