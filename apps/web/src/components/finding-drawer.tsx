"use client";

import { Dialog } from "@base-ui/react/dialog";
import { ExternalLink, X } from "lucide-react";

import { formatEpss, formatRisk, SeverityBadge } from "@/components/severity-badge";
import { advisoryLinks, type Finding } from "@/lib/findings";

type Props = { finding: Finding | null; onClose: () => void };

export function FindingDrawer({ finding, onClose }: Props) {
  return (
    <Dialog.Root open={finding !== null} onOpenChange={(open) => !open && onClose()}>
      <Dialog.Portal>
        <Dialog.Backdrop className="fixed inset-0 bg-black/30" />
        <Dialog.Popup className="bg-background fixed inset-y-0 right-0 w-full max-w-md overflow-y-auto border-l p-6 shadow-xl">
          {finding && <Details finding={finding} />}
          <Dialog.Close
            className="hover:bg-muted absolute top-4 right-4 rounded-md p-1"
            aria-label="Close details"
          >
            <X className="size-4" aria-hidden="true" />
          </Dialog.Close>
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function Details({ finding }: { finding: Finding }) {
  const { dependency } = finding;
  return (
    <div className="space-y-5 pr-6">
      <div className="space-y-1">
        <Dialog.Title className="font-mono text-lg font-semibold break-all">
          {finding.vuln_id}
        </Dialog.Title>
        {/* Summary comes from OSV: rendered as text by React, never as HTML. */}
        <Dialog.Description className="text-muted-foreground text-sm">
          {finding.summary || "No summary in the advisory."}
        </Dialog.Description>
      </div>

      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
        <dt className="text-muted-foreground">Package</dt>
        <dd>
          <span className="font-mono break-all">
            {dependency.name} {dependency.version}
          </span>{" "}
          <span className="text-muted-foreground">
            ({dependency.ecosystem}, {dependency.direct ? "direct" : "transitive"})
          </span>
        </dd>
        <dt className="text-muted-foreground">Risk</dt>
        <dd className="tabular-nums">{formatRisk(finding.risk_score)}</dd>
        <dt className="text-muted-foreground">Severity</dt>
        <dd>
          <SeverityBadge severity={finding.severity} />
          {finding.cvss_score !== null && (
            <span className="text-muted-foreground ml-2">CVSS {finding.cvss_score.toFixed(1)}</span>
          )}
        </dd>
        <dt className="text-muted-foreground">EPSS</dt>
        <dd className="tabular-nums">
          {finding.epss === null ? "No score available" : `${formatEpss(finding.epss)} chance of exploitation in the next 30 days`}
        </dd>
        <dt className="text-muted-foreground">CISA KEV</dt>
        <dd>{finding.in_kev ? "Yes: known to be exploited" : "Not listed"}</dd>
        <dt className="text-muted-foreground">Fixed in</dt>
        <dd className="font-mono">
          {finding.fixed_versions.length ? finding.fixed_versions.join(", ") : "No fix released"}
        </dd>
        {finding.aliases.length > 0 && (
          <>
            <dt className="text-muted-foreground">Also known as</dt>
            <dd className="font-mono break-all">{finding.aliases.join(", ")}</dd>
          </>
        )}
      </dl>

      {finding.risk_score === null && (
        <p className="rounded-md bg-muted px-3 py-2 text-sm">
          Not scored: there is no EPSS score and it isn&apos;t in KEV. That means missing data, not low
          risk.
        </p>
      )}

      <ul className="flex gap-4 text-sm">
        {advisoryLinks(finding).map((link) => (
          <li key={link.href}>
            <a
              href={link.href}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 underline underline-offset-4"
            >
              {link.label}
              <ExternalLink className="size-3" aria-hidden="true" />
            </a>
          </li>
        ))}
      </ul>
    </div>
  );
}
