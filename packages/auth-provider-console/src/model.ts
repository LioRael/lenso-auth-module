export type ProviderKind = "github" | "google" | "oidc";

export type ModuleHttpRouteLike = {
  capability?: string;
  method: string;
  path: string;
};

export type ProviderModuleMetadataLike = {
  delivery: "linked" | "service";
  dependencyModuleIds?: readonly string[];
  moduleId: string;
  releaseDigest: string;
  routes?: readonly ModuleHttpRouteLike[];
  runtimeStatus: "active" | "disabled" | "degraded" | "failed";
  version: string;
};

export type ProviderSummary = {
  dependencies: readonly string[];
  delivery: ProviderModuleMetadataLike["delivery"] | "missing";
  kind: ProviderKind;
  label: string;
  moduleName: string;
  routeCount: number;
  status: "loaded" | "error" | "missing";
  runtimeStatus: ProviderModuleMetadataLike["runtimeStatus"] | "missing";
  version: string;
};

export const providerDefinitions = [
  {
    kind: "github",
    label: "GitHub",
    moduleName: "auth-github",
  },
  {
    kind: "google",
    label: "Google",
    moduleName: "auth-google",
  },
  {
    kind: "oidc",
    label: "OIDC Provider",
    moduleName: "auth-oidc",
  },
] as const;

export function providerSummaries(
  modules: readonly ProviderModuleMetadataLike[]
): ProviderSummary[] {
  return providerDefinitions.map((provider) => {
    const metadata = modules.find(
      (module) => module.moduleId.replace(/^lenso\//u, "") === provider.moduleName
    );
    const status = metadata
      ? metadata.runtimeStatus === "active"
        ? "loaded"
        : "error"
      : "missing";
    return {
      dependencies: metadata?.dependencyModuleIds ?? [],
      delivery: metadata?.delivery ?? "missing",
      kind: provider.kind,
      label: provider.label,
      moduleName: provider.moduleName,
      routeCount: metadata?.routes?.length ?? 0,
      runtimeStatus: metadata?.runtimeStatus ?? "missing",
      status,
      version: metadata?.version ?? "-",
    };
  });
}

export function providerDetail(
  modules: readonly ProviderModuleMetadataLike[],
  kind: ProviderKind
) {
  const summary = providerSummaries(modules).find(
    (provider) => provider.kind === kind
  );
  const metadata = modules.find(
    (module) =>
      module.moduleId.replace(/^lenso\//u, "") === summary?.moduleName
  );
  return {
    routes: metadata?.routes ?? [],
    summary: summary ?? null,
  };
}

export function routeLabel(route: ModuleHttpRouteLike): string {
  return route.path;
}
