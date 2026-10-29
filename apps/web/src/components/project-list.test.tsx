import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ProjectList } from "@/components/project-list";
import { SAMPLE_PROJECTS } from "@/lib/projects";

describe("ProjectList", () => {
  it("shows one row per project with a readable date", () => {
    render(<ProjectList projects={SAMPLE_PROJECTS} />);
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows).toHaveLength(SAMPLE_PROJECTS.length);
    expect(within(rows[0]).getByText("payments-service")).toBeInTheDocument();
    expect(within(rows[0]).getByText("27 Oct 2026")).toBeInTheDocument();
  });

  it("shows a dash for an empty description", () => {
    render(<ProjectList projects={[SAMPLE_PROJECTS[2]]} />);
    expect(screen.getByText("—")).toBeInTheDocument();
  });

  it("shows an empty state instead of an empty table", () => {
    render(<ProjectList projects={[]} />);
    expect(screen.getByText("No projects yet")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("renders HTML in a project name as text, not markup", () => {
    const name = '<img src=x onerror="alert(1)">';
    const { container } = render(<ProjectList projects={[{ ...SAMPLE_PROJECTS[0], name }]} />);
    expect(screen.getByText(name)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
  });
});
