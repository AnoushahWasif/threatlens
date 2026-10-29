import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FindingsTable } from "@/components/findings-table";
import { type Finding, SAMPLE_FINDINGS } from "@/lib/findings";

const packages = () =>
  screen
    .getAllByRole("row")
    .slice(1)
    .map((row) => within(row).getAllByRole("cell")[1].textContent?.split(" ")[0]);

describe("FindingsTable", () => {
  it("starts in risk order with the unscored finding last", () => {
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);
    expect(packages()).toEqual(["log4j-core", "lodash", "jinja2", "pyyaml"]);
    expect(screen.getByRole("columnheader", { name: /Risk/ })).toHaveAttribute(
      "aria-sort",
      "descending",
    );
    expect(screen.getByText("Showing 4 of 4 findings")).toBeInTheDocument();
  });

  it("flips direction on a second click but keeps unscored last", () => {
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);
    fireEvent.click(screen.getByRole("button", { name: /Risk/ }));
    expect(screen.getByRole("columnheader", { name: /Risk/ })).toHaveAttribute(
      "aria-sort",
      "ascending",
    );
    expect(packages()).toEqual(["jinja2", "lodash", "log4j-core", "pyyaml"]);
  });

  it("sorts by package A to Z", () => {
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);
    fireEvent.click(screen.getByRole("button", { name: /Package/ }));
    expect(packages()).toEqual(["jinja2", "lodash", "log4j-core", "pyyaml"]);
  });

  it("filters by severity, KEV and search, and clears", () => {
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);
    const high = screen.getByRole("button", { name: "high" });
    fireEvent.click(high);
    expect(high).toHaveAttribute("aria-pressed", "true");
    expect(packages()).toEqual(["lodash"]);

    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    fireEvent.click(screen.getByLabelText("Known exploited only"));
    expect(packages()).toEqual(["log4j-core"]);

    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    fireEvent.change(screen.getByLabelText(/Search/), { target: { value: "cve-2019-10906" } });
    expect(packages()).toEqual(["jinja2"]);
  });

  it("explains when filters hide everything", () => {
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);
    fireEvent.change(screen.getByLabelText(/Search/), { target: { value: "no-such-package" } });
    expect(screen.getByText("No findings match these filters")).toBeInTheDocument();
    expect(screen.getByText("Showing 0 of 4 findings")).toBeInTheDocument();
    fireEvent.click(screen.getAllByRole("button", { name: "Clear filters" })[0]);
    expect(packages()).toHaveLength(4);
  });

  it("hides Clear filters again once the search box is emptied", () => {
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);
    const search = screen.getByLabelText(/Search/);
    fireEvent.change(search, { target: { value: "x" } });
    fireEvent.change(search, { target: { value: "" } });
    expect(screen.queryByRole("button", { name: "Clear filters" })).not.toBeInTheDocument();
  });

  it("has its own empty state", () => {
    render(<FindingsTable findings={[]} />);
    expect(screen.getByText("No findings")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("opens the drawer from a real button and closes on Escape", async () => {
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);
    const trigger = screen.getByRole("button", { name: "GHSA-35jh-r3h4-6jhm" });
    expect(trigger.tagName).toBe("BUTTON");
    fireEvent.click(trigger);
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByRole("heading", { name: "GHSA-35jh-r3h4-6jhm" })).toBeInTheDocument();
    expect(within(dialog).getByText("4.17.21")).toBeInTheDocument();
    expect(within(dialog).getByText(/21\.3% chance/)).toBeInTheDocument();
    fireEvent.keyDown(dialog, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("explains an unscored finding instead of showing zero", async () => {
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);
    fireEvent.click(screen.getByRole("button", { name: "PYSEC-2021-142" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/missing data, not low/)).toBeInTheDocument();
    expect(within(dialog).queryByText("0")).not.toBeInTheDocument();
  });

  it("renders hostile advisory text as plain text", async () => {
    const hostile: Finding = {
      ...SAMPLE_FINDINGS[0],
      summary: '<img src=x onerror="alert(1)"><script>alert(2)</script>',
    };
    render(<FindingsTable findings={[hostile]} />);
    fireEvent.click(screen.getByRole("button", { name: hostile.vuln_id }));
    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent('<img src=x onerror="alert(1)">');
    expect(document.querySelector("img, script")).toBeNull();
  });

  it("opens advisory links in a new tab without handing over window.opener", async () => {
    render(<FindingsTable findings={SAMPLE_FINDINGS} />);
    fireEvent.click(screen.getByRole("button", { name: "GHSA-jfh8-c2jp-5v3q" }));
    const dialog = await screen.findByRole("dialog");
    const links = within(dialog).getAllByRole("link");
    expect(links.map((a) => a.getAttribute("href"))).toEqual([
      "https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q",
      "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    ]);
    for (const link of links) expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });
});
