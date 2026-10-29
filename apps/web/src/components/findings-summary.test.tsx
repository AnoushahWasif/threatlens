import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FindingsSummary } from "@/components/findings-summary";
import { type Finding, SAMPLE_FINDINGS } from "@/lib/findings";

function stat(label: string) {
  return screen.getByText(label, { selector: "p" }).parentElement!;
}

describe("FindingsSummary", () => {
  it("shows the headline numbers for the sample scan", () => {
    render(<FindingsSummary findings={SAMPLE_FINDINGS} />);
    expect(within(stat("Findings")).getByText("4")).toBeInTheDocument();
    expect(within(stat("In CISA KEV")).getByText("1")).toBeInTheDocument();
    expect(within(stat("Not scored")).getByText("1")).toBeInTheDocument();
    expect(within(stat("Packages affected")).getByText("4")).toBeInTheDocument();
  });

  it("describes each chart in words for screen readers", () => {
    render(<FindingsSummary findings={SAMPLE_FINDINGS} />);
    expect(
      screen.getByRole("img", { name: "Findings by severity: 1 critical, 1 high, 1 medium, 1 unknown." }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("img", { name: "Riskiest package: log4j-core@2.14.1 at 100." }),
    ).toBeInTheDocument();
  });

  it("says unscored packages were left out rather than drawing them as zero", () => {
    render(<FindingsSummary findings={SAMPLE_FINDINGS} />);
    expect(screen.getByText(/1 package not shown/)).toBeInTheDocument();
  });

  it("has the chart data as a table", () => {
    render(<FindingsSummary findings={SAMPLE_FINDINGS} />);
    fireEvent.click(screen.getByText("Show chart data as a table"));
    const packages = screen.getByRole("table", { name: "Riskiest packages" });
    const rows = within(packages).getAllByRole("row").slice(1);
    expect(rows.map((r) => r.textContent)).toEqual([
      "log4j-core@2.14.11001",
      "lodash@4.17.15161",
      "jinja2@2.100.451",
    ]);
    const severities = screen.getByRole("table", { name: "Findings by severity" });
    expect(within(severities).getAllByRole("row")).toHaveLength(6); // header + 5 levels
  });

  it("explains an empty chart when nothing could be scored", () => {
    const unscored: Finding[] = SAMPLE_FINDINGS.map((f) => ({ ...f, risk_score: null }));
    render(<FindingsSummary findings={unscored} />);
    expect(screen.getByText(/No risk scores yet/)).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "No package has a risk score yet." })).toBeInTheDocument();
    expect(screen.getByText(/4 packages not shown/)).toBeInTheDocument();
  });

  it("renders nothing for a project without findings", () => {
    const { container } = render(<FindingsSummary findings={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows hostile package names as text", () => {
    // The API schema already rejects names like this; the component must be safe regardless.
    const log4j = SAMPLE_FINDINGS[1]!;
    const evil = { ...log4j, dependency: { ...log4j.dependency, name: "<img/src/onerror=alert(1)>" } };
    const { container } = render(<FindingsSummary findings={[evil]} />);
    fireEvent.click(screen.getByText("Show chart data as a table"));
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText(/<img\/src\/onerror=alert\(1\)>@2.14.1/)).toBeInTheDocument();
  });
});
