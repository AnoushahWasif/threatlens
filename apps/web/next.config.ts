import type { NextConfig } from "next";

// Static export: the app is plain files on S3 + CloudFront and talks to the API from the
// browser. Security headers (CSP etc.) are set by CloudFront, since `headers()` and
// `proxy.ts` don't exist in an export.
const nextConfig: NextConfig = {
  output: "export",
  images: { unoptimized: true },
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
