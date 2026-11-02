import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ThreatModelView } from "@/components/threat-model-view";
import { ApiError, threatModelBackend, type ThreatModelBackend } from "@/lib/api";
import { resetSampleThreatModels, SAMPLE_MODEL_ID, sampleThreatModels } from "@/lib/sample-threat-models";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, threatModelBackend: vi.fn(actual.threatModelBackend) };
});

const backendMock = vi.mocked(threatModelBackend);

beforeEach(() => {
  resetSampleThreatModels();
  backendMock.mockImplementation(() => sampleThreatModels);
});

afterEach(() => {
  vi.restoreAllMocks();
});

async function open(id = SAMPLE_MODEL_ID) {
  render(<ThreatModelView modelId={id} />);
  return screen.findByRole("heading", { level: 2 });
}

const card = (title: string) => screen.getByRole("listitem", { name: title });

/** The real sample backend, with some calls replaced. */
function withBackend(overrides: Partial<ThreatModelBackend>) {
  backendMock.mockImplementation(() => ({ ...sampleThreatModels, source: "api", ...overrides }));
}

describe("ThreatModelView", () => {
  it("labels sample data and shows counts and STRIDE groups", async () => {
    expect(await open()).toHaveTextContent("payments-service");
    expect(screen.getByText(/Sample data/)).toBeInTheDocument();
    expect(screen.getByText(/2 to review · 1 accepted · 1 rejected/)).toBeInTheDocument();
    const headings = screen.getAllByRole("heading", { level: 3 }).map((h) => h.textContent);
    expect(headings).toEqual(["Spoofing (1)", "Tampering (2)", "Information disclosure (1)"]);
  });

  it("accepts a draft and updates the counts", async () => {
    await open();
    const order = card("Order amount changed in the request");
    fireEvent.click(within(order).getByRole("button", { name: "Accept" }));
    expect(await within(order).findByText("Accepted")).toBeInTheDocument();
    expect(screen.getByText(/1 to review · 2 accepted · 1 rejected/)).toBeInTheDocument();
    expect(within(order).getByRole("button", { name: "Back to review" })).toBeInTheDocument();
  });

  it("edits a threat and marks an AI draft as edited", async () => {
    await open();
    const item = card("Card data written to logs");
    fireEvent.click(within(item).getByRole("button", { name: "Edit" }));
    const editing = screen.getAllByRole("listitem").find((li) => within(li).queryByLabelText("Title"))!;
    fireEvent.change(within(editing).getByLabelText("Title"), { target: { value: "  PAN in logs  " } });
    fireEvent.click(within(editing).getByRole("button", { name: "Save changes" }));
    const saved = await screen.findByRole("listitem", { name: "PAN in logs" });
    expect(within(saved).getByText("AI draft, edited")).toBeInTheDocument();
  });

  it("saving without changes doesn't mark the threat as edited", async () => {
    const updateThreat = vi.fn(sampleThreatModels.updateThreat);
    withBackend({ updateThreat });
    await open();
    fireEvent.click(within(card("Card data written to logs")).getByRole("button", { name: "Edit" }));
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(await screen.findByRole("listitem", { name: "Card data written to logs" })).toBeInTheDocument();
    expect(updateThreat).not.toHaveBeenCalled();
  });

  it("asks before deleting", async () => {
    await open();
    const item = card("SQL injection in order search");
    fireEvent.click(within(item).getByRole("button", { name: "Delete" }));
    fireEvent.click(within(item).getByRole("button", { name: "Keep it" }));
    fireEvent.click(within(item).getByRole("button", { name: "Delete" }));
    fireEvent.click(within(item).getByRole("button", { name: "Confirm delete" }));
    await vi.waitFor(() =>
      expect(screen.queryByRole("listitem", { name: "SQL injection in order search" })).toBeNull(),
    );
  });

  it("checks a new threat before sending it, then adds it as accepted", async () => {
    const addThreat = vi.fn(sampleThreatModels.addThreat);
    withBackend({ addThreat });
    await open();
    fireEvent.click(screen.getByRole("button", { name: "Add a threat" }));
    fireEvent.click(screen.getByRole("button", { name: "Add threat" }));
    expect(screen.getByText("Give the threat a title.")).toBeInTheDocument();
    expect(screen.getByLabelText("Title")).toHaveAttribute("aria-invalid", "true");
    expect(addThreat).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText("STRIDE category"), { target: { value: "repudiation" } });
    fireEvent.change(screen.getByLabelText("Title"), { target: { value: "Refunds not logged" } });
    fireEvent.change(screen.getByLabelText("How an attacker would do it"), {
      target: { value: "Staff deny issuing a refund." },
    });
    fireEvent.click(screen.getByRole("button", { name: "Add threat" }));
    const added = await screen.findByRole("listitem", { name: "Refunds not logged" });
    expect(within(added).getByText("Written by hand")).toBeInTheDocument();
    expect(within(added).getByText("Accepted")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Repudiation (1)" })).toBeInTheDocument();
  });

  it("drafts again without losing reviewed threats", async () => {
    await open();
    fireEvent.click(screen.getByRole("button", { name: "Draft again with AI" }));
    expect(await screen.findByRole("status")).toHaveTextContent(/to review. Anything you had reviewed/);
    // The accepted and the rejected threat are still there.
    expect(within(card("Staff session hijacked to issue refunds")).getByText("Accepted")).toBeInTheDocument();
    expect(within(card("SQL injection in order search")).getByText("Rejected")).toBeInTheDocument();
  });

  it.each([
    ["llm_disabled", undefined, /AI drafting is turned off/],
    ["draft_limit", 90, /Try again in about 2 minutes/],
    ["llm_refused", undefined, /declined to draft/],
  ] as const)("explains a %s draft failure in plain words", async (code, retryAfter, text) => {
    withBackend({ draft: () => Promise.reject(new ApiError("http", 503, code, retryAfter)) });
    await open();
    fireEvent.click(screen.getByRole("button", { name: "Draft again with AI" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(text);
    expect(screen.getByRole("button", { name: "Draft again with AI" })).toBeEnabled();
  });

  it("shows a failed accept on the card and leaves it unchanged", async () => {
    withBackend({ updateThreat: () => Promise.reject(new ApiError("network")) });
    await open();
    const item = card("Order amount changed in the request");
    fireEvent.click(within(item).getByRole("button", { name: "Accept" }));
    expect(await within(item).findByRole("alert")).toHaveTextContent("Can't reach the ThreatLens API.");
    expect(within(item).getByText("To review")).toBeInTheDocument();
  });

  it("filters by status", async () => {
    await open();
    fireEvent.click(screen.getByRole("button", { name: "Rejected" }));
    expect(screen.getByRole("button", { name: "Rejected" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getAllByRole("listitem").map((li) => li.getAttribute("aria-label"))).toEqual([
      "SQL injection in order search",
    ]);
  });

  it("offers a new model, not a retry, when the model doesn't exist", async () => {
    render(<ThreatModelView modelId="00000000-0000-4000-8000-000000000000" />);
    expect(await screen.findByRole("alert")).toHaveTextContent("doesn't exist");
    expect(screen.getByRole("link", { name: "Start a new threat model" })).toHaveAttribute(
      "href",
      "/threat-model",
    );
  });

  it("exports accepted threats as an escaped Markdown file", async () => {
    let blob: Blob | undefined;
    const createObjectURL = vi.fn((b: Blob) => {
      blob = b;
      return "blob:test";
    });
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      expect(this.download).toBe("payments-service-threat-model.md");
    });

    await open();
    fireEvent.click(screen.getByRole("button", { name: "Export Markdown" }));
    expect(click).toHaveBeenCalledOnce();
    const text = await blob!.text();
    expect(text).toContain("### Staff session hijacked to issue refunds");
    expect(text).not.toContain("SQL injection in order search");
    vi.unstubAllGlobals();
  });

  it("can't export before anything is accepted", async () => {
    withBackend({
      get: async (id) => ({ ...(await sampleThreatModels.get(id)), threats: [] }),
    });
    await open();
    expect(screen.getByRole("button", { name: "Export Markdown" })).toBeDisabled();
    expect(screen.getByText(/No threats yet/)).toBeInTheDocument();
  });

  it("shows hostile threat text as text", async () => {
    const evil = "<img src=x onerror=alert(1)>";
    withBackend({
      get: async (id) => {
        const model = await sampleThreatModels.get(id);
        return { ...model, name: evil, threats: [{ ...model.threats[0]!, title: evil, description: evil }] };
      },
    });
    const { container } = render(<ThreatModelView modelId={SAMPLE_MODEL_ID} />);
    expect(await screen.findByRole("heading", { level: 2 })).toHaveTextContent(evil);
    expect(container.querySelector("img")).toBeNull();
  });
});
