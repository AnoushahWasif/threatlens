import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { FindingsView } from "@/components/findings-view";
import { ApiError, fetchFindings } from "@/lib/api";
import { SAMPLE_FINDINGS } from "@/lib/findings";

vi.mock("@/lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/api")>()),
  fetchFindings: vi.fn(),
}));

const mocked = vi.mocked(fetchFindings);
const ID = "3f6c2a1e-8d4b-4c7a-9e21-5b0d7f3a9c11";

beforeEach(() => {
  mocked.mockReset();
});

describe("FindingsView", () => {
  it("loads, then labels sample data", async () => {
    mocked.mockResolvedValue({ source: "sample", findings: SAMPLE_FINDINGS });
    render(<FindingsView projectId={ID} />);
    expect(screen.getByLabelText("Loading findings")).toBeInTheDocument();
    expect(await screen.findByText(/Sample data/)).toBeInTheDocument();
    expect(mocked).toHaveBeenCalledWith(ID, expect.anything());
  });

  it("does not label real API data as sample", async () => {
    mocked.mockResolvedValue({ source: "api", findings: SAMPLE_FINDINGS });
    render(<FindingsView projectId={ID} />);
    expect(await screen.findByText("log4j-core")).toBeInTheDocument();
    expect(screen.queryByText(/Sample data/)).not.toBeInTheDocument();
  });

  it("offers a way back, not a retry, for a missing project", async () => {
    mocked.mockRejectedValue(new ApiError("not-found"));
    render(<FindingsView projectId="nope" />);
    expect(await screen.findByRole("alert")).toHaveTextContent("doesn't exist");
    expect(screen.getByRole("link", { name: "Back to projects" })).toHaveAttribute("href", "/");
    expect(screen.queryByRole("button", { name: "Try again" })).not.toBeInTheDocument();
  });

  it("retries after a network error", async () => {
    mocked
      .mockRejectedValueOnce(new ApiError("network"))
      .mockResolvedValueOnce({ source: "api", findings: SAMPLE_FINDINGS });
    render(<FindingsView projectId={ID} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Can't reach the ThreatLens API.");
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("lodash")).toBeInTheDocument();
  });

  it("never shows a raw exception message", async () => {
    mocked.mockRejectedValue(new Error("secret stack detail at line 42"));
    render(<FindingsView projectId={ID} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Something went wrong while loading findings.",
    );
    expect(screen.queryByText(/secret stack/)).not.toBeInTheDocument();
  });
});
