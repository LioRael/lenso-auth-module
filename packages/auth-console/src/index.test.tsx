import { describe, expect, test } from "vitest";

import { authConsoleManifest } from "./manifest";

describe("auth console UI artifact", () => {
  test("declares only isolated bridge entries", () => {
    expect(authConsoleManifest.source).toBe("isolated_ui_artifact");
    expect(authConsoleManifest.bridgeProtocol).toBe("lenso.console-bridge.v1");
    expect(authConsoleManifest.surfaces.map((surface) => surface.entry)).toEqual([
      "index.html?surface=sessions",
      "index.html?surface=users",
    ]);
  });
});
