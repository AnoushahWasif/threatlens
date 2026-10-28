# Secure SDLC notes (mapped to CSSLP domains)

ThreatLens is also my practice ground for the CSSLP (ISC2 Certified Secure Software Lifecycle Professional). This file maps what's actually built to the eight CSSLP domains, with links to the code or test that shows it. Only things that exist go here; planned work stays in [ARCHITECTURE.md](ARCHITECTURE.md).

## 1. Secure software concepts

| Principle | Where |
|-----------|-------|
| Fail secure | An OSV outage marks dependencies "not checked", never "clean" ([osv.py](../apps/api/src/threatlens_api/osv.py), `test_persistent_outage_marks_dependencies_unchecked`). An EPSS or KEV outage marks the scan incomplete, and a finding without data stays unscored instead of scoring 0 ([risk.py](../apps/api/src/threatlens_api/risk.py), `test_epss_outage_leaves_findings_unscored_and_result_incomplete`) |
| Least information | Error responses never echo input or stack traces ([main.py](../apps/api/src/threatlens_api/main.py), `test_app.py`) |
| Complete mediation | Every request goes through one middleware for request ids, size limit and headers, including crashes |
| Economy of mechanism | Risk score is one formula with three inputs (EPSS, KEV, severity), pinned by unit tests, not a black-box model |

## 2. Secure software lifecycle management

- Architecture and a STRIDE threat model were written before any code ([ARCHITECTURE.md](ARCHITECTURE.md)).
- Every design choice is recorded with its reason in the Decisions table.
- Pre-commit hooks and CI run on every change: ruff (including the bandit `S` rules), pytest, gitleaks.

## 3. Secure software requirements

Security requirements written as tests, so they can't silently regress:

- Production refuses wildcard CORS, plain-http origins and short API keys (`test_settings.py`).
- Uploads over 5 MB or 20,000 dependencies are refused (`test_ingest.py`).
- Unknown JSON fields are rejected, not dropped (`test_models.py`).

## 4. Secure software architecture and design

- STRIDE threat model with a mitigation per threat ([ARCHITECTURE.md](ARCHITECTURE.md#threat-model-of-threatlens-stride)).
- Trust boundaries named: browser ↔ API, API ↔ outside APIs, worker ↔ uploaded files.
- Outside data is untrusted even from a reputable source: OSV responses are size-limited, schema-checked and their ids validated before use.
- LLM output is a draft that needs human acceptance (decision 3).

## 5. Secure software implementation

| Weakness (CWE) | Control |
|----------------|---------|
| CWE-20 improper input validation | Strict pydantic models with patterns on package names, versions and vuln ids |
| CWE-22 path traversal | Vuln ids from OSV must match `^[A-Z][A-Z0-9]*-…$` before they go into a URL path (`test_hostile_vuln_ids_never_reach_a_url`) |
| CWE-400 resource exhaustion | Size, count and nesting limits on uploads; response size cap, page cap and bounded cache for OSV; size caps on EPSS (1 MB) and KEV (20 MB) responses |
| CWE-674 uncontrolled recursion | Nested CycloneDX walked with an explicit stack |
| CWE-918 SSRF | OSV, EPSS and KEV clients have fixed base URLs and never follow redirects (`test_redirects_are_not_followed`, `test_redirect_is_not_followed`) |
| CWE-345 insufficient verification of data | EPSS values must be finite probabilities; rows for CVEs we didn't ask about are dropped; a KEV feed with a wrong count or under 1000 entries is rejected (`test_values_that_are_not_probabilities_fail_the_chunk`, `test_count_mismatch_is_rejected`) |
| CWE-209 info in error messages | One error shape, only `loc` and `msg` from validation |
| CWE-1333 ReDoS | Regexes are anchored with bounded repetition, no nested quantifiers |

## 6. Secure software testing

- Failure modes are tested, not just the happy path: crashes, malformed input, hostile ids, outages, endless pagination.
- Third-party API tests run on responses recorded from the real service, so the parser is tested against the real format without network flakiness.
- 219 tests, run in CI on every push.

## 7. Secure deployment, operations and maintenance

- API docs (`/docs`, `/openapi.json`) are off in production.
- Security headers on every response: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cache-Control: no-store`, and a deny-all `Content-Security-Policy`.
- Request ids on every response for tracing incidents across logs.
- Secrets only through environment variables (`.env.example` has no real values); Secrets Manager on AWS.

## 8. Secure software supply chain

This is what ThreatLens itself does for other projects, and it applies the same to itself:

- Dependencies are pinned in `uv.lock` and Dependabot is on for the repo.
- Gitleaks in CI and GitHub push protection catch committed secrets.
- SBOM ingest (CycloneDX) and vulnerability lookup against OSV are the core feature.
- Known-vulnerable versions come with the version that fixes them, taken only from the matching package's record.
