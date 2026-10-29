import Link from "next/link";
import { ShieldCheck } from "lucide-react";

export function SiteHeader() {
  return (
    <header className="border-b">
      <div className="mx-auto flex h-14 max-w-5xl items-center gap-6 px-4">
        <Link href="/" className="flex items-center gap-2 font-semibold">
          <ShieldCheck className="size-5" aria-hidden="true" />
          ThreatLens
        </Link>
        <nav aria-label="Main" className="text-sm">
          <Link href="/" className="text-foreground">
            Projects
          </Link>
        </nav>
      </div>
    </header>
  );
}
