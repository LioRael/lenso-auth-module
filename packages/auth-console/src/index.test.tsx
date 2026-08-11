import { describe, expect, test } from "vitest";

import { authConsoleManifest } from "./manifest";

describe("auth console UI artifact", () => {
  test("declares release-owned ESM surfaces", () => {
    expect(authConsoleManifest.moduleId).toBe("lenso/auth");
    expect(authConsoleManifest.surfaces.map((surface) => surface.id)).toEqual([
      "sessions",
      "users",
    ]);
    expect(authConsoleManifest.surfaces.map((surface) => surface.path)).toEqual([
      "/auth/sessions",
      "/auth/users",
    ]);
    expect(authConsoleManifest.surfaces[0]?.navigation?.group).toEqual({
      icon: "users",
      id: "directory",
      label: "Directory",
      order: 10,
    });
    expect(authConsoleManifest.surfaces.map((surface) => surface.icon)).toEqual([
      "activity",
      "users",
    ]);
  });
});
