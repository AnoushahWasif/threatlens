"use client";

import { useSearchParams } from "next/navigation";
import { Suspense } from "react";

import { SignIn } from "@/components/sign-in";

function SignInBody() {
  return <SignIn next={useSearchParams().get("next")} />;
}

export default function SignInPage() {
  return (
    <section className="space-y-6">
      <h1 className="text-2xl font-semibold tracking-tight">Sign in</h1>
      <Suspense fallback={null}>
        <SignInBody />
      </Suspense>
    </section>
  );
}
