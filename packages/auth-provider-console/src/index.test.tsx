import { describe, expect, test } from "vitest";

import {
  AuthProvidersPage,
  GitHubProviderPage,
  GoogleProviderPage,
  OidcProviderPage,
  authProviderConsoleManifest,
  authProviderConsoleModule,
} from ".";

describe("auth provider console package", () => {
  test("declares provider console package surfaces", () => {
    expect(authProviderConsoleManifest).toMatchObject({
      exportName: "authProviderConsoleModule",
      packageName: "@lenso/auth-provider-console",
      source: "runtime_bundle",
      surfaces: [
        {
          label: "Providers",
          route: "/data/auth/providers",
          surfaceName: "providers",
        },
        {
          label: "GitHub",
          route: "/data/auth/providers/github",
          surfaceName: "github",
        },
        {
          label: "Google",
          route: "/data/auth/providers/google",
          surfaceName: "google",
        },
        {
          label: "OIDC Provider",
          route: "/data/auth/providers/oidc",
          surfaceName: "oidc",
        },
      ],
      version: "workspace",
    });
    expect(authProviderConsoleModule.surfaces.map((surface) => surface.path)).toEqual([
      "/data/auth/providers",
      "/data/auth/providers/github",
      "/data/auth/providers/google",
      "/data/auth/providers/oidc",
    ]);
    expect(AuthProvidersPage).toBeTypeOf("function");
    expect(GitHubProviderPage).toBeTypeOf("function");
    expect(GoogleProviderPage).toBeTypeOf("function");
    expect(OidcProviderPage).toBeTypeOf("function");
  });
});
