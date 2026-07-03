import { describe, expect, test } from "vitest";

import { providerDetail, providerSummaries, routeLabel } from "./model";

const modules = [
  {
    dependencies: ["auth", "auth-oauth"],
    http_routes: [
      {
        display_name: "Start GitHub Login",
        method: "get",
        path: "/v1/auth/github/start",
      },
      {
        display_name: "Complete GitHub Login",
        method: "get",
        path: "/v1/auth/github/callback",
      },
    ],
    module_name: "auth-github",
    status: "loaded" as const,
  },
];

describe("auth provider console model", () => {
  test("summarizes installed provider modules", () => {
    expect(providerSummaries(modules)).toEqual([
      {
        dependencies: ["auth", "auth-oauth"],
        error: "-",
        kind: "github",
        label: "GitHub",
        moduleName: "auth-github",
        routeCount: 2,
        status: "loaded",
      },
      {
        dependencies: [],
        error: "-",
        kind: "google",
        label: "Google",
        moduleName: "auth-google",
        routeCount: 0,
        status: "missing",
      },
      {
        dependencies: [],
        error: "-",
        kind: "oidc",
        label: "OIDC Provider",
        moduleName: "auth-oidc",
        routeCount: 0,
        status: "missing",
      },
    ]);
  });

  test("selects provider detail routes", () => {
    expect(providerDetail(modules, "github").routes).toHaveLength(2);
    expect(routeLabel(modules[0]!.http_routes![0]!)).toBe(
      "Start GitHub Login"
    );
  });
});
