import { defineConsolePackageManifest } from "@lenso/runtime-console-api";

import consoleSurface from "../console-surface.json";

const providerSurface = {
  area: "data",
  icon: "network",
  navigation: {
    order: 80,
    workspace: {
      icon: "shield",
      id: "auth",
      label: "Auth",
    },
  },
  requiredCapabilities: [],
} as const;

const consoleSurfaceContract = consoleSurface as unknown as {
  readonly exportName: "authProviderConsoleModule";
  readonly id: "auth-provider";
  readonly packageName: "@lenso/auth-provider-console";
  readonly source: "runtime_bundle";
  readonly surfaces: readonly [
    typeof providerSurface & {
      readonly label: "Providers";
      readonly route: "/data/auth/providers";
      readonly surfaceName: "providers";
    },
    typeof providerSurface & {
      readonly label: "GitHub";
      readonly route: "/data/auth/providers/github";
      readonly surfaceName: "github";
    },
    typeof providerSurface & {
      readonly label: "Google";
      readonly route: "/data/auth/providers/google";
      readonly surfaceName: "google";
    },
    Omit<typeof providerSurface, "icon"> & {
      readonly icon: "shield";
      readonly label: "OIDC Provider";
      readonly route: "/data/auth/providers/oidc";
      readonly surfaceName: "oidc";
    },
  ];
  readonly version: "workspace";
};

export const authProviderConsoleManifest = defineConsolePackageManifest(
  consoleSurfaceContract
);
