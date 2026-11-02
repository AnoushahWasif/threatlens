import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuthProvider, RequireAuth } from "@/components/auth-provider";
import { SignIn } from "@/components/sign-in";
import { UserMenu } from "@/components/user-menu";
import { requestLocalToken } from "@/lib/api";
import { clearSession, endSession, readSession, saveSession } from "@/lib/session";

const replace = vi.fn();
vi.mock("next/navigation", () => ({ useRouter: () => ({ replace, push: vi.fn() }) }));
vi.mock("@/lib/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/api")>()),
  requestLocalToken: vi.fn(),
}));

const tokenMock = vi.mocked(requestLocalToken);
const HOUR = 3_600_000;

function page(children: React.ReactNode) {
  return render(
    <AuthProvider>
      <UserMenu />
      {children}
    </AuthProvider>,
  );
}

beforeEach(() => {
  replace.mockReset();
  tokenMock.mockReset();
  clearSession();
  vi.stubEnv("NEXT_PUBLIC_API_URL", "https://api.threatlens.dev");
  window.history.replaceState(null, "", "/findings?project=abc");
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("RequireAuth", () => {
  it("sends a signed-out visitor to sign in, remembering where they were", async () => {
    page(<RequireAuth>secret page</RequireAuth>);
    await vi.waitFor(() =>
      expect(replace).toHaveBeenCalledWith(`/sign-in?next=${encodeURIComponent("/findings?project=abc")}`),
    );
    expect(screen.queryByText("secret page")).toBeNull();
  });

  it("shows the page to a signed-in user, with their name and a way out", async () => {
    saveSession({ accessToken: "t".repeat(40), username: "anoushah", expiresAt: Date.now() + HOUR });
    page(<RequireAuth>secret page</RequireAuth>);
    expect(await screen.findByText("secret page")).toBeInTheDocument();
    expect(screen.getByText("anoushah")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    expect(readSession()).toBeNull();
    await vi.waitFor(() => expect(replace).toHaveBeenCalled());
    expect(screen.queryByText("secret page")).toBeNull();
  });

  it("hides the page as soon as the API rejects the token", async () => {
    saveSession({ accessToken: "t".repeat(40), username: "anoushah", expiresAt: Date.now() + HOUR });
    page(<RequireAuth>secret page</RequireAuth>);
    await screen.findByText("secret page");
    act(() => endSession());
    await vi.waitFor(() => expect(screen.queryByText("secret page")).toBeNull());
    expect(replace).toHaveBeenCalled();
  });

  it("needs no sign-in when there's no API (sample data)", async () => {
    vi.stubEnv("NEXT_PUBLIC_API_URL", "");
    page(<RequireAuth>sample page</RequireAuth>);
    expect(await screen.findByText("sample page")).toBeInTheDocument();
    expect(replace).not.toHaveBeenCalled();
  });

  it("shows a setup error instead of a sign-in loop when auth is misconfigured", async () => {
    vi.stubEnv("NEXT_PUBLIC_AUTH_MODE", "cognito");
    vi.stubEnv("NEXT_PUBLIC_COGNITO_DOMAIN", "http://not-https.example");
    page(<RequireAuth>secret page</RequireAuth>);
    expect(await screen.findByRole("alert")).toHaveTextContent("isn't set up correctly");
    expect(replace).not.toHaveBeenCalled();
  });
});

describe("local sign-in", () => {
  it("checks the username before asking the API", async () => {
    page(<SignIn next="/findings" />);
    fireEvent.change(await screen.findByLabelText("Username"), { target: { value: "Bad Name" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(screen.getByRole("alert")).toHaveTextContent("lower-case letters");
    expect(tokenMock).not.toHaveBeenCalled();
  });

  it("signs in and goes back to a safe next page only", async () => {
    tokenMock.mockResolvedValue({ access_token: "t".repeat(40), token_type: "Bearer", expires_in: 3600 });
    page(<SignIn next="//evil.example/steal" />);
    fireEvent.change(await screen.findByLabelText("Username"), { target: { value: "alice" } });
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await vi.waitFor(() => expect(replace).toHaveBeenCalledWith("/"));
    expect(readSession()?.username).toBe("alice");
    expect(screen.getByRole("button", { name: "Sign out" })).toBeInTheDocument();
  });

  it("says it's for development only", async () => {
    page(<SignIn next={null} />);
    expect(await screen.findByText(/any name works and no password is checked/)).toBeInTheDocument();
  });
});
