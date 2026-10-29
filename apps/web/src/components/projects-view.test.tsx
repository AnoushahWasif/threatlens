import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ProjectsView } from "@/components/projects-view";
import { ApiError, fetchProjects } from "@/lib/api";
import { SAMPLE_PROJECTS } from "@/lib/projects";

vi.mock("@/lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/api")>()),
  fetchProjects: vi.fn(),
}));

const mocked = vi.mocked(fetchProjects);

beforeEach(() => {
  mocked.mockReset();
});

describe("ProjectsView", () => {
  it("shows a loading state, then the projects", async () => {
    mocked.mockResolvedValue({ source: "api", projects: SAMPLE_PROJECTS });
    render(<ProjectsView />);
    expect(screen.getByLabelText("Loading projects")).toBeInTheDocument();
    expect(await screen.findByText("payments-service")).toBeInTheDocument();
    expect(screen.queryByText(/Sample data/)).not.toBeInTheDocument();
  });

  it("labels sample data so it is never mistaken for real results", async () => {
    mocked.mockResolvedValue({ source: "sample", projects: SAMPLE_PROJECTS });
    render(<ProjectsView />);
    expect(await screen.findByText(/Sample data/)).toBeInTheDocument();
  });

  it("shows a fixed error message and recovers on retry", async () => {
    mocked
      .mockRejectedValueOnce(new ApiError("network"))
      .mockResolvedValueOnce({ source: "api", projects: SAMPLE_PROJECTS });
    render(<ProjectsView />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Can't reach the ThreatLens API.");
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("payments-service")).toBeInTheDocument();
    expect(mocked).toHaveBeenCalledTimes(2);
  });

  it("never shows the text of an unexpected exception", async () => {
    mocked.mockRejectedValue(new Error("stack trace with internal hostname db-01"));
    render(<ProjectsView />);
    const alert = await screen.findByRole("alert");
    expect(alert).not.toHaveTextContent("db-01");
    expect(alert).toHaveTextContent("Something went wrong while loading projects.");
  });
});
