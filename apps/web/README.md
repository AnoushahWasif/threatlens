# web

Next.js frontend, built as a static export (`out/`) for S3 + CloudFront. It calls the API from the browser.

```bash
corepack enable          # once, gives you the pinned pnpm
pnpm install             # from the repo root
cd apps/web
pnpm dev                 # http://localhost:3000
pnpm test                # vitest
pnpm lint && pnpm typecheck
pnpm build               # writes out/
```

Needs Node 22.12 or newer (Vite 8 / Vitest 5).

Without `NEXT_PUBLIC_API_URL` the project list runs on labelled sample data. The projects API arrives on Day 13.

Security headers (CSP, HSTS, frame options) are not set here: a static export has no server, so CloudFront adds them (Day 15/16).
