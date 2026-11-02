import { AuthCallback } from "@/components/sign-in";

export default function AuthCallbackPage() {
  return (
    <section className="space-y-6">
      <h1 className="text-2xl font-semibold tracking-tight">Signing in</h1>
      <AuthCallback />
    </section>
  );
}
