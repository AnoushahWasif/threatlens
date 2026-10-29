const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export class ConfigError extends Error {}

/**
 * The API base URL, or null when none is set (the app then shows sample data).
 * NEXT_PUBLIC_ values are baked into the browser bundle, so this must never hold a secret.
 */
export function apiBaseUrl(raw: string | undefined = process.env.NEXT_PUBLIC_API_URL): string | null {
  const value = raw?.trim();
  if (!value) return null;

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new ConfigError("NEXT_PUBLIC_API_URL is not a valid URL");
  }
  const local = LOCAL_HOSTS.has(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) {
    throw new ConfigError("NEXT_PUBLIC_API_URL must use https (http only for localhost)");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new ConfigError("NEXT_PUBLIC_API_URL must be a plain base URL");
  }
  return url.origin + url.pathname.replace(/\/+$/, "");
}
