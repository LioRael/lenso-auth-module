import { describe, expect, test } from "vitest";

import { authDeviceConsoleManifest } from "./manifest";

describe("auth device console UI artifact", () => {
  test("declares a release-owned ESM entry", () => {
    expect(authDeviceConsoleManifest).toMatchObject({
      moduleId: "lenso/auth-device",
      surfaces: [
        {
          icon: "smartphone",
          id: "devices",
          navigation: {
            group: {
              icon: "users",
              id: "directory",
              label: "Directory",
              order: 10,
            },
          },
          path: "/auth/devices",
        },
      ],
    });
  });
});
