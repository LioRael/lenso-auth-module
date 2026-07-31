import { describe, expect, test } from "vitest";

import { authDeviceConsoleManifest } from "./manifest";

describe("auth device console UI artifact", () => {
  test("declares an isolated bridge entry", () => {
    expect(authDeviceConsoleManifest).toMatchObject({
      source: "isolated_ui_artifact",
      bridgeProtocol: "lenso.console-bridge.v1",
      surfaces: [{ entry: "index.html?surface=devices" }],
    });
  });
});
