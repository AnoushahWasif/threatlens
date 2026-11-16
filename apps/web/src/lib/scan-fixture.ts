// A finished scan as the API returns it, for tests.
import type { Scan } from "@/lib/scans";

export const SCAN: Scan = {
  id: "7a1d2c3b-4e5f-4a6b-8c7d-9e0f1a2b3c4d",
  project_id: "0b8f6a52-3c1d-4e9a-8f27-6d5c4b3a2e10",
  filename: "requirements.txt",
  format: "requirements.txt",
  status: "done",
  dependencies: 12,
  skipped: 0,
  skipped_examples: [],
  findings: 3,
  unchecked: 0,
  epss_failed: 0,
  kev_available: true,
  kev_stale: false,
  error: null,
};
