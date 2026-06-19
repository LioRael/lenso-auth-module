import { defineConsolePackageManifest } from "@lenso/runtime-console-api";

import consoleSurface from "../console-surface.json";

const consoleSurfaceContract = consoleSurface as unknown as {
  readonly exportName: "authConsoleModule";
  readonly id: "auth";
  readonly packageName: "@lenso/auth-console";
  readonly source: "runtime_bundle";
  readonly surfaces: readonly [
    {
      readonly area: "data";
      readonly icon: "shield";
      readonly label: "Sessions";
      readonly navigation: {
        readonly order: 50;
        readonly workspace: {
          readonly icon: "shield";
          readonly id: "auth";
          readonly label: "Auth";
        };
      };
      readonly requiredCapabilities: readonly ["auth.users.read"];
      readonly route: "/data/auth";
      readonly surfaceName: "auth";
    },
    {
      readonly area: "data";
      readonly icon: "shield";
      readonly label: "Sessions";
      readonly navigation: {
        readonly order: 50;
        readonly workspace: {
          readonly icon: "shield";
          readonly id: "auth";
          readonly label: "Auth";
        };
      };
      readonly requiredCapabilities: readonly ["auth.users.read"];
      readonly route: "/data/auth/sessions";
      readonly surfaceName: "sessions";
    },
    {
      readonly area: "data";
      readonly icon: "shield";
      readonly label: "Users";
      readonly navigation: {
        readonly order: 60;
        readonly workspace: {
          readonly icon: "shield";
          readonly id: "auth";
          readonly label: "Auth";
        };
      };
      readonly requiredCapabilities: readonly ["auth.users.read"];
      readonly route: "/data/auth/users";
      readonly surfaceName: "users";
    },
  ];
  readonly version: "workspace";
};

export const authConsoleManifest = defineConsolePackageManifest(
  consoleSurfaceContract
);
