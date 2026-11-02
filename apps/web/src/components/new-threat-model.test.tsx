import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { NewThreatModel } from "@/components/new-threat-model";
import { ApiError, threatModelBackend } from "@/lib/api";
import { resetSampleThreatModels, SAMPLE_MODEL_ID, sampleThreatModels } from "@/lib/sample-threat-models";

const push = vi.fn();
vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));
vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, threatModelBackend: vi.fn(actual.threatModelBackend) };
});

const backendMock = vi.mocked(threatModelBackend);
const ARCH = "A FastAPI app behind an ALB talks to Stripe and stores orders in Postgres.";
const UUID = /^\/threat-model\?id=[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

beforeEach(() => {
  push.mockReset();
  resetSampleThreatModels();
  backendMock.mockImplementation(() => sampleThreatModels);
});

function fill(name: string, architecture: string) {
  fireEvent.change(screen.getByLabelText("Name"), { target: { value: name } });
  fireEvent.change(screen.getByLabelText("Architecture description"), { target: { value: architecture } });
  fireEvent.click(screen.getByRole("button", { name: "Create threat model" }));
}

describe("NewThreatModel", () => {
  it("links to the sample model in sample mode", () => {
    render(<NewThreatModel />);
    expect(screen.getByRole("link", { name: "Open the sample model" })).toHaveAttribute(
      "href",
      `/threat-model?id=${SAMPLE_MODEL_ID}`,
    );
  });

  it("warns that the text goes to the AI", () => {
    render(<NewThreatModel />);
    expect(screen.getByLabelText("Architecture description")).toHaveAccessibleDescription(
      /sent to the AI when you draft, so leave out secrets/,
    );
  });

  it("checks the fields before creating anything", () => {
    const create = vi.fn();
    backendMock.mockImplementation(() => ({ ...sampleThreatModels, create }));
    render(<NewThreatModel />);
    fill(" ", "too short");
    expect(screen.getByText("Give the model a name.")).toBeInTheDocument();
    expect(screen.getByText(/at least 40 characters/)).toBeInTheDocument();
    expect(create).not.toHaveBeenCalled();
    expect(push).not.toHaveBeenCalled();
  });

  it("creates the model with trimmed text and opens it", async () => {
    const create = vi.fn(sampleThreatModels.create);
    backendMock.mockImplementation(() => ({ ...sampleThreatModels, create }));
    render(<NewThreatModel />);
    fill("  payments  ", `  ${ARCH}  `);
    await vi.waitFor(() => expect(push).toHaveBeenCalledOnce());
    expect(create).toHaveBeenCalledWith({ name: "payments", architecture: ARCH });
    expect(push.mock.calls[0]![0]).toMatch(UUID);
  });

  it("shows a server failure and lets you try again", async () => {
    backendMock.mockImplementation(() => ({
      ...sampleThreatModels,
      create: () => Promise.reject(new ApiError("http", 507, "storage_full")),
    }));
    render(<NewThreatModel />);
    fill("payments", ARCH);
    expect(await screen.findByRole("alert")).toHaveTextContent("no room for more threat models");
    expect(screen.getByRole("button", { name: "Create threat model" })).toBeEnabled();
    expect(push).not.toHaveBeenCalled();
  });

  it("shows a counter that turns red past the limit", () => {
    render(<NewThreatModel />);
    fireEvent.change(screen.getByLabelText("Architecture description"), {
      target: { value: "a".repeat(8_001) },
    });
    expect(screen.getByText("8,001 / 8,000 characters")).toHaveClass("text-destructive");
  });
});
