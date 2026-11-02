import { ApiError } from "@/lib/api-error";
import type { ThreatModelBackend } from "@/lib/api";
import {
  LIMITS,
  type ModelInput,
  type Threat,
  type ThreatInput,
  type ThreatModel,
  type ThreatPatch,
} from "@/lib/threats";

// In-memory stand-in for the API, so the page works with no API configured. It follows the
// same rules as apps/api/src/threatlens_api/store.py. Everything is lost on reload.

export const SAMPLE_MODEL_ID = "5d2c8b1e-7a4f-4c3d-9e6b-1f0a2d3c4b5e";
export const SAMPLE_DRAFTER = "sample drafts (no LLM)";

const T0 = "2026-10-31T09:00:00Z";

function threat(fields: ThreatInput & Partial<Threat>): Threat {
  return {
    id: crypto.randomUUID(),
    status: "draft",
    source: "llm",
    edited: false,
    created_at: T0,
    updated_at: T0,
    ...fields,
  };
}

const ARCHITECTURE =
  "payments-service: a FastAPI app behind an AWS ALB. Customers' browsers post card details " +
  "to /checkout, which forwards them to Stripe and stores the order in Postgres (RDS). " +
  "An admin dashboard on the same app lets staff issue refunds. Logs go to CloudWatch.";

// Fixed text standing in for an LLM draft. Clearly not from a model: see SAMPLE_DRAFTER.
const SAMPLE_DRAFTS: ThreatInput[] = [
  {
    category: "spoofing",
    component: "Admin dashboard",
    title: "Staff session hijacked to issue refunds",
    description: "A stolen admin session cookie lets an attacker issue refunds to cards they control.",
    mitigation: "Require MFA for staff, short admin sessions, and re-authentication before a refund.",
  },
  {
    category: "tampering",
    component: "/checkout",
    title: "Order amount changed in the request",
    description: "The browser sends the total; an attacker edits it before it reaches Stripe.",
    mitigation: "Compute the amount on the server from the cart; never trust a client-sent total.",
  },
  {
    category: "repudiation",
    component: "Refunds",
    title: "No record of who issued a refund",
    description: "A staff member issues a fraudulent refund and there is no log tying it to them.",
    mitigation: "Write an append-only audit log entry with the staff id for every refund.",
  },
  {
    category: "information_disclosure",
    component: "CloudWatch logs",
    title: "Card data written to logs",
    description: "Request logging captures the checkout body, putting card numbers in CloudWatch.",
    mitigation: "Never log request bodies on /checkout; redact card-like fields in the logger.",
  },
  {
    category: "denial_of_service",
    component: "/checkout",
    title: "Card testing floods checkout",
    description: "Bots try thousands of stolen cards, running up Stripe fees and getting the account flagged.",
    mitigation: "Rate limit per IP and per session, add a CAPTCHA after failed payments.",
  },
  {
    category: "elevation_of_privilege",
    component: "Admin dashboard",
    title: "Customer reaches admin routes",
    description: "Admin routes are on the same app and rely on a hidden link instead of a role check.",
    mitigation: "Check the staff role on every admin route, server side, with a test per route.",
  },
];

function seed(): Map<string, ThreatModel> {
  const [spoof, tamper, , disclose] = SAMPLE_DRAFTS;
  return new Map([
    [
      SAMPLE_MODEL_ID,
      {
        id: SAMPLE_MODEL_ID,
        name: "payments-service",
        architecture: ARCHITECTURE,
        drafted_with: SAMPLE_DRAFTER,
        drafted_at: T0,
        created_at: T0,
        threats: [
          threat({ ...spoof!, status: "accepted" }),
          threat({ ...tamper! }),
          threat({ ...disclose! }),
          threat({
            category: "tampering",
            component: "Postgres",
            title: "SQL injection in order search",
            description: "The admin order search builds SQL from the query string.",
            mitigation: "Use parameterised queries only.",
            status: "rejected",
          }),
        ],
      },
    ],
  ]);
}

const key = (t: ThreatInput) => `${t.category}:${t.title.toLowerCase()}`;
const TEXT_FIELDS = ["category", "title", "description", "mitigation", "component"] as const;
const now = () => new Date().toISOString();

let models = seed();

/** Tests start from a fresh copy. */
export function resetSampleThreatModels() {
  models = seed();
}

function checkUnique(model: ThreatModel, input: ThreatInput, ignore?: string) {
  if (model.threats.some((t) => t.id !== ignore && key(t) === key(input))) {
    throw new ApiError("http", 409, "duplicate_threat");
  }
}

function find(id: string): ThreatModel {
  const model = models.get(id);
  if (!model) throw new ApiError("not-found", 404, "not_found");
  return model;
}

function findThreat(model: ThreatModel, threatId: string): number {
  const index = model.threats.findIndex((t) => t.id === threatId);
  if (index === -1) throw new ApiError("not-found", 404, "not_found");
  return index;
}

// Copies out, so the page can't change the store by mutating what it was given.
const copy = <T>(value: T): T => structuredClone(value);

export const sampleThreatModels: ThreatModelBackend = {
  source: "sample",

  async create(input: ModelInput) {
    const model: ThreatModel = {
      id: crypto.randomUUID(),
      name: input.name,
      architecture: input.architecture,
      threats: [],
      drafted_with: null,
      drafted_at: null,
      created_at: now(),
    };
    models.set(model.id, model);
    return copy(model);
  },

  async get(id) {
    return copy(find(id));
  },

  async draft(id) {
    const model = find(id);
    const kept = model.threats.filter(
      (t) => !(t.source === "llm" && t.status === "draft" && !t.edited),
    );
    const seen = new Set(kept.map(key));
    const added = SAMPLE_DRAFTS.filter((d) => !seen.has(key(d)))
      .slice(0, Math.max(0, LIMITS.threats - kept.length))
      .map((d) => threat({ ...d, created_at: now(), updated_at: now() }));
    model.threats = [...kept, ...added];
    model.drafted_with = SAMPLE_DRAFTER;
    model.drafted_at = now();
    return { model: copy(model), added: added.length, dropped: SAMPLE_DRAFTS.length - added.length };
  },

  async addThreat(id, input) {
    const model = find(id);
    if (model.threats.length >= LIMITS.threats) {
      throw new ApiError("http", 409, "too_many_threats");
    }
    checkUnique(model, input);
    const added = threat({ ...input, status: "accepted", source: "manual", created_at: now(), updated_at: now() });
    model.threats.push(added);
    return copy(added);
  },

  async updateThreat(id, threatId, patch: ThreatPatch) {
    const model = find(id);
    const index = findThreat(model, threatId);
    const current = model.threats[index]!;
    const edited = current.edited || TEXT_FIELDS.some((f) => f in patch && patch[f] !== current[f]);
    const updated = { ...current, ...patch, edited, updated_at: now() };
    checkUnique(model, updated, threatId);
    model.threats[index] = updated;
    return copy(updated);
  },

  async deleteThreat(id, threatId) {
    const model = find(id);
    model.threats.splice(findThreat(model, threatId), 1);
  },
};
