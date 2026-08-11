export type ProviderKind = "github" | "google" | "oidc";

export type ProviderConfigurationField = {
  description: string;
  name: string;
  requirement: "Required" | "Runtime";
  source: "Runtime config" | "Secret store";
  state: "Configured" | "Protected";
};

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
  configuration: readonly ProviderConfigurationField[];
  dependencies: readonly string[];
  delivery: ProviderModuleMetadataLike["delivery"] | "missing";
  kind: ProviderKind;
  label: string;
  moduleName: string;
  operations: string;
  routeCount: number;
  routeSummary: string;
  status: "loaded" | "error" | "missing";
  surfacePath: string;
  runtimeStatus: ProviderModuleMetadataLike["runtimeStatus"] | "missing";
  version: string;
};

export const providerDefinitions = [
  {
    kind: "github",
    label: "GitHub",
    moduleName: "auth-github",
    operations: "Start sign-in · Complete callback",
    routeSummary: "Start + complete",
    surfacePath: "/auth/providers/github",
    configuration: [
      {
        description: "OAuth application id",
        name: "client_id",
        requirement: "Required",
        source: "Secret store",
        state: "Configured",
      },
      {
        description: "OAuth application secret",
        name: "client_secret",
        requirement: "Required",
        source: "Secret store",
        state: "Protected",
      },
      {
        description: "Authorized callback",
        name: "redirect_uri",
        requirement: "Required",
        source: "Runtime config",
        state: "Configured",
      },
    ],
  },
  {
    kind: "google",
    label: "Google",
    moduleName: "auth-google",
    operations: "Start sign-in · Complete callback",
    routeSummary: "Start + complete",
    surfacePath: "/auth/providers/google",
    configuration: [
      {
        description: "OAuth application id",
        name: "client_id",
        requirement: "Required",
        source: "Secret store",
        state: "Configured",
      },
      {
        description: "OAuth application secret",
        name: "client_secret",
        requirement: "Required",
        source: "Secret store",
        state: "Protected",
      },
      {
        description: "Authorized callback",
        name: "redirect_uri",
        requirement: "Required",
        source: "Runtime config",
        state: "Configured",
      },
    ],
  },
  {
    kind: "oidc",
    label: "OIDC Provider",
    moduleName: "auth-oidc",
    operations: "Discovery · Authorization · Token",
    routeSummary: "Discovery + token",
    surfacePath: "/auth/providers/oidc",
    configuration: [
      {
        description: "Public issuer identifier",
        name: "issuer",
        requirement: "Runtime",
        source: "Runtime config",
        state: "Configured",
      },
      {
        description: "Console OAuth client",
        name: "console_client_id",
        requirement: "Required",
        source: "Secret store",
        state: "Protected",
      },
      {
        description: "Allowed Console callbacks",
        name: "console_redirect_uris",
        requirement: "Runtime",
        source: "Runtime config",
        state: "Configured",
      },
    ],
  },
] as const;

export function providerDefinition(kind: ProviderKind) {
  return providerDefinitions.find((provider) => provider.kind === kind)!;
}

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
      configuration: provider.configuration,
      dependencies: metadata?.dependencyModuleIds ?? [],
      delivery: metadata?.delivery ?? "missing",
      kind: provider.kind,
      label: provider.label,
      moduleName: provider.moduleName,
      operations: provider.operations,
      routeCount: metadata?.routes?.length ?? 0,
      routeSummary: provider.routeSummary,
      runtimeStatus: metadata?.runtimeStatus ?? "missing",
      status,
      surfacePath: provider.surfacePath,
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

export function providerRouteDescription(route: ModuleHttpRouteLike): {
  purpose: string;
  summary: string;
} {
  if (route.path.endsWith("openid-configuration")) {
    return { purpose: "Discovery", summary: "Discovery document" };
  }
  if (route.path.endsWith("jwks.json")) {
    return { purpose: "JWKS", summary: "Signing keys" };
  }
  if (route.path.endsWith("authorize")) {
    return { purpose: "OAuth", summary: "Authorization endpoint" };
  }
  if (route.path.endsWith("token")) {
    return { purpose: "OAuth", summary: "Token endpoint" };
  }
  if (route.path.endsWith("start")) {
    return { purpose: "Sign-in", summary: "Start login" };
  }
  if (route.path.endsWith("callback")) {
    return { purpose: "Sign-in", summary: "Complete callback" };
  }
  return { purpose: route.method, summary: route.path };
}
