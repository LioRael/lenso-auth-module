import { defineConsolePackageManifest } from "@lenso/runtime-console-api";

import consoleSurface from "../console-surface.json";

const consoleSurfaceContract = consoleSurface as unknown as {
  readonly exportName: "authDeviceConsoleModule";
  readonly id: "auth-device";
  readonly packageName: "@lenso/auth-device-console";
  readonly source: "runtime_bundle";
  readonly surfaces: readonly [
    {
      readonly area: "data";
      readonly icon: "network";
      readonly label: "Devices";
      readonly navigation: {
        readonly order: 70;
        readonly workspace: {
          readonly icon: "shield";
          readonly id: "auth";
          readonly label: "Auth";
        };
      };
      readonly requiredCapabilities: readonly ["auth_device.devices.read"];
      readonly route: "/data/auth/devices";
      readonly surfaceName: "devices";
    },
  ];
  readonly version: "workspace";
};

export const authDeviceConsoleManifest = defineConsolePackageManifest(
  consoleSurfaceContract
);
