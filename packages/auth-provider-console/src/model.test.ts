import { describe, expect, test } from "vitest";

import { providerDetail, providerSummaries, routeLabel } from "./model";

const modules = [
  {
    delivery: "service" as const,
    dependencyModuleIds: ["lenso/auth", "lenso/auth-oauth"],
    moduleId: "lenso/auth-github",
    releaseDigest: "sha256:github",
    routes: [
      {
        method: "GET",
        path: "/v1/auth/github/start",
      },
      {
        method: "GET",
        path: "/v1/auth/github/callback",
      },
    ],
    runtimeStatus: "active" as const,
    version: "0.1.5",
  },
];

describe("auth provider console model", () => {
  test("summarizes inventory-owned provider modules", () => {
    expect(providerSummaries(modules)).toEqual([
      {
        dependencies: ["lenso/auth", "lenso/auth-oauth"],
        delivery: "service",
        kind: "github",
        label: "GitHub",
        moduleName: "auth-github",
        routeCount: 2,
        runtimeStatus: "active",
        status: "loaded",
        version: "0.1.5",
      },
      {
        dependencies: [],
        delivery: "missing",
        kind: "google",
        label: "Google",
        moduleName: "auth-google",
        routeCount: 0,
        runtimeStatus: "missing",
        status: "missing",
        version: "-",
      },
      {
        dependencies: [],
        delivery: "missing",
        kind: "oidc",
        label: "OIDC Provider",
        moduleName: "auth-oidc",
        routeCount: 0,
        runtimeStatus: "missing",
        status: "missing",
        version: "-",
      },
    ]);
  });

  test("selects provider detail routes", () => {
    expect(providerDetail(modules, "github").routes).toHaveLength(2);
    expect(routeLabel(modules[0]!.routes![0]!)).toBe(
      "/v1/auth/github/start"
    );
  });
});
