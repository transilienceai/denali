export type SharedGcpProject = { id: string; number: string };

export function parseSharedGcpProjects(text: string): SharedGcpProject[] {
  const projects = text.split(/\n|,/).filter((line) => line.trim()).map((line) => {
    const [id, number, extra] = line.trim().split(/\s*:\s*/);
    if (!id || !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(id) || !number ||
      !/^[0-9]{6,20}$/.test(number) || extra !== undefined) {
      throw new Error("Enter each exact project as project-id:project-number");
    }
    return { id, number };
  });
  if (!projects.length || projects.length > 8) throw new Error("Select 1–8 exact Google Cloud projects");
  if (new Set(projects.map((project) => project.id)).size !== projects.length ||
    new Set(projects.map((project) => project.number)).size !== projects.length) {
    throw new Error("Project IDs and numbers must be unique");
  }
  return projects.sort((left, right) => left.id.localeCompare(right.id));
}

export function sharedGcpNotEnabled(error: unknown): boolean {
  // Only Denali's default-off / non-pilot 404 hides the section. Broker failures
  // remain visible and must not cause an automatic native connection creation.
  return error instanceof Error && "status" in error && error.status === 404;
}

export function sharedGcpCanRetry(status: { retry_available?: boolean } | null, availability: string): boolean {
  // Platform computes expiration using its database clock. Never infer a stale
  // lease from a browser timer or start a second legitimate active job.
  return availability !== "disabled" && status?.retry_available === true;
}
