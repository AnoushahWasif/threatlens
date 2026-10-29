import Link from "next/link";

export default function NotFound() {
  return (
    <section className="space-y-2">
      <h1 className="text-2xl font-semibold tracking-tight">Page not found</h1>
      <Link href="/" className="text-sm underline underline-offset-4">
        Back to projects
      </Link>
    </section>
  );
}
