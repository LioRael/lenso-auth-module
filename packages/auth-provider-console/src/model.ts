export type ProviderKind = "github" | "google" | "oidc";

export type ModuleHttpRouteLike = {
  display_name?: string | null;
  method?: string;
  path?: string;
  story_title?: string | null;
};

export type ProviderModuleMetadataLike = {
  dependencies?: readonly string[];
  error?: string | null;
  http_routes?: readonly ModuleHttpRouteLike[];
  module_name?: string;
  status?: "loaded" | "error";
};

export type ProviderSummary = {
  dependencies: readonly string[];
  error: string;
  kind: ProviderKind;
  label: string;
  moduleName: string;
  routeCount: number;
  status: "loaded" | "error" | "missing";
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
      (module) => module.module_name === provider.moduleName
    );
    return {
      dependencies: metadata?.dependencies ?? [],
      error: metadata?.error ?? "-",
      kind: provider.kind,
      label: provider.label,
      moduleName: provider.moduleName,
      routeCount: metadata?.http_routes?.length ?? 0,
      status: metadata?.status ?? "missing",
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
    (module) => module.module_name === summary?.moduleName
  );
  return {
    routes: metadata?.http_routes ?? [],
    summary: summary ?? null,
  };
}

export function routeLabel(route: ModuleHttpRouteLike): string {
  return route.display_name || route.story_title || route.path || "-";
}
