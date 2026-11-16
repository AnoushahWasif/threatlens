import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ScanUpload } from "@/components/scan-upload";
import { ApiError, fetchScan, uploadScan } from "@/lib/api";
import { SCAN } from "@/lib/scan-fixture";
import { MAX_FOLLOW_MS, type Scan } from "@/lib/scans";

vi.mock("@/lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/api")>()),
  uploadScan: vi.fn(),
  fetchScan: vi.fn(),
}));

const upload = vi.mocked(uploadScan);
const status = vi.mocked(fetchScan);
const PROJECT = SCAN.project_id;
const queued: Scan = { ...SCAN, status: "queued", findings: 0 };

function choose(name: string, text = "jinja2==2.10\n") {
  const input = screen.getByLabelText("Scan a lockfile or SBOM");
  fireEvent.change(input, { target: { files: [new File([text], name)] } });
}

const submit = () => fireEvent.click(screen.getByRole("button", { name: "Scan" }));

/** Lets the given time pass, with React updates and pending promises settled. */
const wait = (ms: number) => act(() => vi.advanceTimersByTimeAsync(ms));

beforeEach(() => {
  vi.useFakeTimers();
  upload.mockReset();
  status.mockReset();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("ScanUpload", () => {
  it("uploads, follows the scan to the end and reports once", async () => {
    upload.mockResolvedValue(queued);
    status
      .mockResolvedValueOnce({ ...queued, status: "running" })
      .mockResolvedValueOnce(SCAN);
    const onScanned = vi.fn();
    render(<ScanUpload projectId={PROJECT} onScanned={onScanned} />);
    choose("requirements.txt");
    submit();
    await wait(0);
    expect(upload).toHaveBeenCalledWith(PROJECT, expect.any(File));
    expect(screen.getByText(/Waiting for a worker/)).toBeInTheDocument();

    await wait(2_000);
    expect(screen.getByText(/Checking packages/)).toBeInTheDocument();
    await wait(2_000);
    expect(screen.getByText("3 findings in 12 packages.", { exact: false })).toBeInTheDocument();
    expect(onScanned).toHaveBeenCalledTimes(1);

    // Finished: no more checks.
    await wait(60_000);
    expect(status).toHaveBeenCalledTimes(2);
  });

  it("checks the file before sending anything", async () => {
    render(<ScanUpload projectId={PROJECT} onScanned={vi.fn()} />);
    submit();
    expect(screen.getByRole("alert")).toHaveTextContent("Choose a file first.");
    choose("empty.txt", "");
    submit();
    expect(screen.getByRole("alert")).toHaveTextContent("That file is empty.");
    expect(upload).not.toHaveBeenCalled();
  });

  it("shows a fixed message for a refused file, and stays usable", async () => {
    upload.mockRejectedValueOnce(new ApiError("http", 422, "bad_file"));
    render(<ScanUpload projectId={PROJECT} onScanned={vi.fn()} />);
    choose("notes.md");
    submit();
    await wait(0);
    expect(screen.getByRole("alert")).toHaveTextContent("couldn't read that file");
    expect(screen.getByRole("button", { name: "Scan" })).toBeEnabled();
    expect(status).not.toHaveBeenCalled();
  });

  it("a failed scan shows the worker's reason and loads no findings", async () => {
    upload.mockResolvedValue(queued);
    status.mockResolvedValue({ ...queued, status: "failed", error: "The scan kept failing. Try again later" });
    const onScanned = vi.fn();
    render(<ScanUpload projectId={PROJECT} onScanned={onScanned} />);
    choose("uv.lock");
    submit();
    await wait(2_000);
    expect(screen.getByText(/The scan kept failing/)).toBeInTheDocument();
    expect(onScanned).not.toHaveBeenCalled();
  });

  it("rides out a few failed checks", async () => {
    upload.mockResolvedValue(queued);
    status
      .mockRejectedValueOnce(new ApiError("network"))
      .mockRejectedValueOnce(new ApiError("timeout"))
      .mockResolvedValueOnce(SCAN);
    render(<ScanUpload projectId={PROJECT} onScanned={vi.fn()} />);
    choose("uv.lock");
    submit();
    await wait(6_000);
    expect(screen.getByText(/3 findings/)).toBeInTheDocument();
  });

  it("stops after five failed checks in a row", async () => {
    upload.mockResolvedValue(queued);
    status.mockRejectedValue(new ApiError("network"));
    render(<ScanUpload projectId={PROJECT} onScanned={vi.fn()} />);
    choose("uv.lock");
    submit();
    await wait(20_000);
    expect(screen.getByText(/Lost touch with the scan/)).toBeInTheDocument();
    expect(status).toHaveBeenCalledTimes(5);
    // Can start another.
    expect(screen.getByRole("button", { name: "Scan" })).toBeEnabled();
  });

  it("stops at once if the session ends", async () => {
    upload.mockResolvedValue(queued);
    status.mockRejectedValue(new ApiError("unauthorized", 401));
    render(<ScanUpload projectId={PROJECT} onScanned={vi.fn()} />);
    choose("uv.lock");
    submit();
    await wait(10_000);
    expect(screen.getByText("Your session has ended. Sign in again.")).toBeInTheDocument();
    expect(status).toHaveBeenCalledTimes(1);
  });

  it("gives up following after the time limit", async () => {
    upload.mockResolvedValue(queued);
    status.mockResolvedValue(queued);
    let clock = 0;
    render(<ScanUpload projectId={PROJECT} onScanned={vi.fn()} now={() => clock} />);
    choose("uv.lock");
    submit();
    await wait(2_000);
    clock = MAX_FOLLOW_MS + 1;
    await wait(5_000);
    expect(screen.getByText(/taking unusually long/)).toBeInTheDocument();
    const calls = status.mock.calls.length;
    await wait(60_000);
    expect(status).toHaveBeenCalledTimes(calls);
  });

  it("stops checking when the page goes away", async () => {
    upload.mockResolvedValue(queued);
    status.mockResolvedValue(queued);
    const { unmount } = render(<ScanUpload projectId={PROJECT} onScanned={vi.fn()} />);
    choose("uv.lock");
    submit();
    await wait(2_000);
    unmount();
    const calls = status.mock.calls.length;
    await wait(60_000);
    expect(status).toHaveBeenCalledTimes(calls);
  });

  it("lists what was skipped, and how many more", async () => {
    upload.mockResolvedValue(queued);
    status.mockResolvedValue({
      ...SCAN,
      skipped: 25,
      skipped_examples: [{ ref: "flask>=2.0", reason: "not pinned to an exact version" }],
    });
    render(<ScanUpload projectId={PROJECT} onScanned={vi.fn()} />);
    choose("requirements.txt");
    submit();
    await wait(2_000);
    expect(screen.getByText("25 entries skipped")).toBeInTheDocument();
    expect(screen.getByText("flask>=2.0")).toBeInTheDocument();
    expect(screen.getByText("and 24 more")).toBeInTheDocument();
  });
});
