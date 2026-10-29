import { z } from "zod";

// Mirrors `Project` in apps/api/src/threatlens_api/models.py.
export const projectSchema = z.object({
  id: z.uuid(),
  name: z.string().min(1).max(100),
  description: z.string().max(5_000),
  created_at: z.iso.datetime({ offset: true }),
});

export const MAX_PROJECTS = 500;
export const projectListSchema = z.array(projectSchema).max(MAX_PROJECTS);

export type Project = z.infer<typeof projectSchema>;

export const SAMPLE_PROJECTS: Project[] = [
  {
    id: "3f6c2a1e-8d4b-4c7a-9e21-5b0d7f3a9c11",
    name: "payments-service",
    description: "Python API that takes card payments. requirements.txt + architecture notes.",
    created_at: "2026-10-27T09:12:00Z",
  },
  {
    id: "a1b9e4d2-6f3c-4e8a-b7d5-2c9f0e1a4b36",
    name: "storefront-web",
    description: "Next.js shop front, package-lock.json v3.",
    created_at: "2026-10-28T14:40:00Z",
  },
  {
    id: "c7e2f9a4-1b6d-4d3e-8a5f-9e0b2d7c1f48",
    name: "legacy-reports",
    description: "",
    created_at: "2026-10-29T08:05:00Z",
  },
];
