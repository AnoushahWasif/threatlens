import Link from "next/link";
import { ShieldCheck } from "lucide-react";

import { UserMenu } from "@/components/user-menu";

export function SiteHeader() {
  return (
    <header className="border-b">
      <div className="mx-auto flex h-14 max-w-5xl items-center gap-4 px-4 sm:gap-6">
        <Link href="/" className="flex items-center gap-2 font-semibold">
          <ShieldCheck className="size-5" aria-hidden="true" />
          ThreatLens
        </Link>
        <nav aria-label="Main" className="flex gap-3 text-sm whitespace-nowrap sm:gap-4">
          <Link href="/" className="text-foreground">
            Projects
          </Link>
          <Link href="/threat-model" className="text-foreground">
            Threat model
          </Link>
        </nav>
        <UserMenu />
      </div>
    </header>
  );
}
