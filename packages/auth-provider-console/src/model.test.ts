import { describe, expect, test } from "vitest";

import {
  providerDetail,
  providerRouteDescription,
  providerSummaries,
  routeLabel,
} from "./model";

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
    expect(
      providerSummaries(modules).map(
        ({
          kind,
          label,
          moduleName,
          routeCount,
          routeSummary,
          status,
          surfacePath,
        }) => ({
          kind,
          label,
          moduleName,
          routeCount,
          routeSummary,
          status,
          surfacePath,
        })
      )
    ).toEqual([
      {
        kind: "github",
        label: "GitHub",
        moduleName: "auth-github",
        routeCount: 2,
        routeSummary: "Start + complete",
        status: "loaded",
        surfacePath: "/auth/providers/github",
      },
      {
        kind: "google",
        label: "Google",
        moduleName: "auth-google",
        routeCount: 0,
        routeSummary: "Start + complete",
        status: "missing",
        surfacePath: "/auth/providers/google",
      },
      {
        kind: "oidc",
        label: "OIDC Provider",
        moduleName: "auth-oidc",
        routeCount: 0,
        routeSummary: "Discovery + token",
        status: "missing",
        surfacePath: "/auth/providers/oidc",
      },
    ]);

    expect(providerSummaries(modules)[0]?.configuration).toHaveLength(3);
  });

  test("selects provider detail routes", () => {
    expect(providerDetail(modules, "github").routes).toHaveLength(2);
    expect(routeLabel(modules[0]!.routes![0]!)).toBe(
      "/v1/auth/github/start"
    );
  });

  test("describes provider and protocol routes without exposing secrets", () => {
    expect(
      providerRouteDescription({
        method: "GET",
        path: "/.well-known/openid-configuration",
      })
    ).toEqual({ purpose: "Discovery", summary: "Discovery document" });
    expect(
      providerRouteDescription({
        method: "GET",
        path: "/v1/auth/github/start",
      })
    ).toEqual({ purpose: "Sign-in", summary: "Start login" });
  });
});
