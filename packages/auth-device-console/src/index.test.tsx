import { describe, expect, test } from "vitest";

import { authDeviceConsoleManifest } from "./manifest";

describe("auth device console UI artifact", () => {
  test("declares a release-owned ESM entry", () => {
    expect(authDeviceConsoleManifest).toMatchObject({
      moduleId: "lenso/auth-device",
      surfaces: [{ id: "devices", path: "/data/auth/devices" }],
    });
  });
});
