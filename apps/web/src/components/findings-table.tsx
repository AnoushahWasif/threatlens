"use client";

import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import { useMemo, useState } from "react";

import { FindingDrawer } from "@/components/finding-drawer";
import { formatEpss, formatRisk, SeverityBadge } from "@/components/severity-badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DEFAULT_SORT,
  type Filter,
  filterFindings,
  type Finding,
  MAX_QUERY_LENGTH,
  NO_FILTER,
  SEVERITIES,
  type Severity,
  type Sort,
  type SortKey,
  sortFindings,
} from "@/lib/findings";

const COLUMNS: { key: SortKey; label: string; numeric?: boolean }[] = [
  { key: "risk", label: "Risk", numeric: true },
  { key: "package", label: "Package" },
  { key: "severity", label: "Severity" },
  { key: "epss", label: "EPSS", numeric: true },
];

export function FindingsTable({ findings }: { findings: Finding[] }) {
  const [sort, setSort] = useState<Sort>(DEFAULT_SORT);
  const [filter, setFilter] = useState<Filter>(NO_FILTER);
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const rows = useMemo(
    () => sortFindings(filterFindings(findings, filter), sort),
    [findings, filter, sort],
  );
  const selected = findings.find((f) => f.id === selectedId) ?? null;
  const filtered = filter.severities.size > 0 || filter.kevOnly || filter.query.trim() !== "";

  if (findings.length === 0) {
    return (
      <div className="rounded-lg border border-dashed p-10 text-center">
        <p className="font-medium">No findings</p>
        <p className="text-muted-foreground mt-1 text-sm">
          None of the checked dependencies has a known vulnerability in OSV.
        </p>
      </div>
    );
  }

  const toggleSeverity = (severity: Severity) =>
    setFilter((current) => {
      const severities = new Set(current.severities);
      if (severities.has(severity)) severities.delete(severity);
      else severities.add(severity);
      return { ...current, severities };
    });

  const sortBy = (key: SortKey) =>
    setSort((current) =>
      current.key === key
        ? { key, direction: current.direction === "desc" ? "asc" : "desc" }
        : // Text reads A→Z first; numbers and severity start with the worst.
          { key, direction: key === "package" ? "asc" : "desc" },
    );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3" role="group" aria-label="Filters">
        <input
          type="search"
          placeholder="Search package or ID"
          aria-label="Search package or vulnerability ID"
          maxLength={MAX_QUERY_LENGTH}
          value={filter.query}
          onChange={(e) => setFilter((f) => ({ ...f, query: e.target.value }))}
          className="h-8 w-56 rounded-md border px-2 text-sm"
        />
        <div className="flex gap-1">
          {SEVERITIES.map((severity) => (
            <Button
              key={severity}
              size="sm"
              variant={filter.severities.has(severity) ? "default" : "outline"}
              aria-pressed={filter.severities.has(severity)}
              onClick={() => toggleSeverity(severity)}
              className="capitalize"
            >
              {severity}
            </Button>
          ))}
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={filter.kevOnly}
            onChange={(e) => setFilter((f) => ({ ...f, kevOnly: e.target.checked }))}
          />
          Known exploited only
        </label>
        {filtered && (
          <Button size="sm" variant="ghost" onClick={() => setFilter(NO_FILTER)}>
            Clear filters
          </Button>
        )}
      </div>

      <p className="text-muted-foreground text-sm" aria-live="polite">
        Showing {rows.length} of {findings.length} findings
      </p>

      {rows.length === 0 ? (
        <div className="rounded-lg border border-dashed p-8 text-center">
          <p className="font-medium">No findings match these filters</p>
          <Button size="sm" variant="outline" className="mt-3" onClick={() => setFilter(NO_FILTER)}>
            Clear filters
          </Button>
        </div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              {COLUMNS.map((column) => (
                <TableHead
                  key={column.key}
                  className={column.numeric ? "text-right" : undefined}
                  aria-sort={
                    sort.key === column.key
                      ? sort.direction === "asc"
                        ? "ascending"
                        : "descending"
                      : undefined
                  }
                >
                  <button
                    type="button"
                    onClick={() => sortBy(column.key)}
                    className="inline-flex items-center gap-1 font-medium"
                  >
                    {column.label}
                    <SortIcon active={sort.key === column.key} direction={sort.direction} />
                  </button>
                </TableHead>
              ))}
              <TableHead>KEV</TableHead>
              <TableHead>Vulnerability</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((finding) => (
              <TableRow key={finding.id}>
                <TableCell className="text-right font-medium tabular-nums">
                  {finding.risk_score === null ? (
                    <span className="text-muted-foreground font-normal">Not scored</span>
                  ) : (
                    formatRisk(finding.risk_score)
                  )}
                </TableCell>
                <TableCell className="font-mono text-sm">
                  {finding.dependency.name}{" "}
                  <span className="text-muted-foreground">{finding.dependency.version}</span>
                </TableCell>
                <TableCell>
                  <SeverityBadge severity={finding.severity} />
                </TableCell>
                <TableCell className="text-right tabular-nums">{formatEpss(finding.epss)}</TableCell>
                <TableCell>{finding.in_kev ? <span className="font-medium">Exploited</span> : ""}</TableCell>
                <TableCell>
                  <button
                    type="button"
                    onClick={() => setSelectedId(finding.id)}
                    className="font-mono text-sm underline underline-offset-4"
                  >
                    {finding.vuln_id}
                  </button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <FindingDrawer finding={selected} onClose={() => setSelectedId(null)} />
    </div>
  );
}

function SortIcon({ active, direction }: { active: boolean; direction: Sort["direction"] }) {
  const Icon = !active ? ArrowUpDown : direction === "asc" ? ArrowUp : ArrowDown;
  return <Icon className={`size-3.5 ${active ? "" : "opacity-40"}`} aria-hidden="true" />;
}
