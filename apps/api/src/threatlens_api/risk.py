"""Turn OSV results into ranked findings: how likely is it to be exploited, and how bad is it.

    risk = 100 x likelihood x severity weight
    likelihood = 1.0 if the CVE is in CISA KEV, else its EPSS probability

No EPSS score and not in KEV means the finding is left unscored (risk None), never 0.
"""

from dataclasses import dataclass, field
from uuid import UUID

from threatlens_api.epss import CVE_ID, EpssClient
from threatlens_api.kev import KevCatalog, KevClient, KevError
from threatlens_api.models import Dependency, Finding, Severity
from threatlens_api.osv import ScanResult, Vuln

WEIGHTS = {
    Severity.CRITICAL: 1.0,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
    # Unknown is not "low": PYSEC records often have no label at all.
    Severity.UNKNOWN: 0.5,
}


def risk_score(severity: Severity, epss: float | None, in_kev: bool) -> float | None:
    if in_kev:
        likelihood = 1.0
    elif epss is None:
        return None
    else:
        likelihood = epss
    # 3 places: removes float noise but keeps EPSS 0.99999 (99.999) apart from a KEV 100.
    return round(100 * likelihood * WEIGHTS[severity], 3)


def cves(vuln: Vuln) -> list[str]:
    return [i for i in (vuln.id, *vuln.aliases) if CVE_ID.match(i)]


def rank_key(finding: Finding) -> tuple:
    unscored = finding.risk_score is None
    return (
        unscored,
        -(finding.risk_score or 0),
        -WEIGHTS[finding.severity],
        finding.dependency.name,
        finding.vuln_id,
    )


def rank(findings: list[Finding]) -> list[Finding]:
    """Highest risk first; unscored findings after all scored ones, worst severity first."""
    return sorted(findings, key=rank_key)


@dataclass
class Enriched:
    findings: list[Finding] = field(default_factory=list)
    unchecked: list[Dependency] = field(default_factory=list)  # OSV could not check these
    epss_failed: set[str] = field(default_factory=set)
    kev_available: bool = True
    kev_stale: bool = False

    @property
    def complete(self) -> bool:
        return not self.unchecked and not self.epss_failed and self.kev_available


def enrich(
    project_id: UUID, deps: list[Dependency], scan: ScanResult, epss: EpssClient, kev: KevClient
) -> Enriched:
    result = Enriched(unchecked=list(scan.failed))
    by_key = {(d.ecosystem, d.name, d.version): d for d in deps}

    catalog: KevCatalog | None
    try:
        catalog = kev.catalog()
        result.kev_stale = catalog.stale
    except KevError:
        catalog, result.kev_available = None, False

    all_cves = [c for vulns in scan.vulns.values() for v in vulns for c in cves(v)]
    scores = epss.scores(all_cves)
    result.epss_failed = scores.failed

    for dep_key, vulns in scan.vulns.items():
        dep = by_key[dep_key]
        for vuln in vulns:
            ids = cves(vuln)
            known = [scores.scores[c].epss for c in ids if c in scores.scores]
            best = max(known) if known else None
            in_kev = catalog is not None and any(c in catalog for c in ids)
            result.findings.append(
                Finding(
                    project_id=project_id,
                    dependency=dep,
                    vuln_id=vuln.id,
                    aliases=list(vuln.aliases),
                    summary=vuln.summary,
                    severity=vuln.severity,
                    epss=best,
                    in_kev=in_kev,
                    risk_score=risk_score(vuln.severity, best, in_kev),
                    fixed_versions=vuln.fixed_versions(dep),
                )
            )
    result.findings = rank(result.findings)
    return result
