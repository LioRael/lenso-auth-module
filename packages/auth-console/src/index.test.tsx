import { describe, expect, test } from "vitest";

import {
  AuthSessionsPage,
  AuthUsersPage,
  authConsoleManifest,
  authConsoleModule,
} from ".";

describe("auth console package", () => {
  test("declares an installable auth console package export", () => {
    expect(authConsoleManifest).toMatchObject({
      exportName: "authConsoleModule",
      packageName: "@lenso/auth-console",
      source: "runtime_bundle",
      surfaces: [
        {
          icon: "shield",
          label: "Sessions",
          route: "/data/auth",
          surfaceName: "auth",
        },
        {
          icon: "key-round",
          label: "Sessions",
          route: "/data/auth/sessions",
          surfaceName: "sessions",
        },
        {
          icon: "users",
          label: "Users",
          route: "/data/auth/users",
          surfaceName: "users",
        },
      ],
      version: "workspace",
    });
    expect(authConsoleModule).toMatchObject({
      id: "auth",
      surfaces: [
        {
          label: "Sessions",
          path: "/data/auth",
        },
        {
          label: "Sessions",
          path: "/data/auth/sessions",
        },
        {
          label: "Users",
          path: "/data/auth/users",
        },
      ],
    });
    expect(AuthSessionsPage).toBeTypeOf("function");
    expect(AuthUsersPage).toBeTypeOf("function");
  });
});
