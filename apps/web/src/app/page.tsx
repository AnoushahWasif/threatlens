import { ProjectsView } from "@/components/projects-view";

export default function ProjectsPage() {
  return (
    <section className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Projects</h1>
        <p className="text-muted-foreground text-sm">
          Each project is one codebase: its dependencies, findings and threat model.
        </p>
      </div>
      <ProjectsView />
    </section>
  );
}
