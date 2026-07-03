import { describe, expect, test } from "vitest";

import {
  AuthDevicesPage,
  authDeviceConsoleManifest,
  authDeviceConsoleModule,
} from ".";

describe("auth device console package", () => {
  test("declares an installable auth-device console package export", () => {
    expect(authDeviceConsoleManifest).toMatchObject({
      exportName: "authDeviceConsoleModule",
      packageName: "@lenso/auth-device-console",
      source: "runtime_bundle",
      surfaces: [
        {
          icon: "network",
          label: "Devices",
          route: "/data/auth/devices",
          surfaceName: "devices",
        },
      ],
      version: "workspace",
    });
    expect(authDeviceConsoleModule).toMatchObject({
      id: "auth-device",
      surfaces: [
        {
          label: "Devices",
          path: "/data/auth/devices",
        },
      ],
    });
    expect(AuthDevicesPage).toBeTypeOf("function");
  });
});
