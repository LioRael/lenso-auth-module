import { describe, expect, test } from "vitest";

import { authProviderConsoleManifest } from "./manifest";

describe("auth provider console UI artifact", () => {
  test("binds every provider surface to the isolated artifact", () => {
    expect(authProviderConsoleManifest.source).toBe("isolated_ui_artifact");
    expect(authProviderConsoleManifest.bridgeProtocol).toBe("lenso.console-bridge.v1");
    expect(authProviderConsoleManifest.surfaces.map((surface) => surface.entry)).toEqual([
      "providers",
      "github-provider",
      "google-provider",
      "oidc-provider",
    ]);
  });
});
