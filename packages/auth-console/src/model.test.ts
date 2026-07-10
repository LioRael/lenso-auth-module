import { describe, expect, test } from "vitest";

import {
  CONSOLE_ADMIN_USER_SCOPES_CONFIG_KEY,
  CONSOLE_ACCESS_PRESETS,
  DEFAULT_CONSOLE_ADMIN_SCOPES,
  authSessionRows,
  authSessionsSummary,
  authUserRows,
  authUsersSummary,
  consoleAccessPresetId,
  consoleAdminAccessForUser,
  consoleAdminUserScopes,
  setConsoleAdminUserAccess,
  setConsoleUserScopes,
} from "./model";

describe("auth console model", () => {
  test("formats auth user records from admin data", () => {
    const now = new Date("2026-06-18T12:00:00.000Z");
    const users = [
      {
        created_at: "2026-06-18T09:00:00.000Z",
        disabled_at: null,
        disabled_reason: null,
        disabled_until: null,
        id: "usr_active",
      },
      {
        created_at: "2026-06-17T09:00:00.000Z",
        disabled_at: "2026-06-18T10:00:00.000Z",
        disabled_reason: "abuse",
        disabled_until: "2026-06-19T10:00:00.000Z",
        id: "usr_disabled",
      },
      {
        created_at: "2026-06-16T09:00:00.000Z",
        disabled_at: "2026-06-17T10:00:00.000Z",
        disabled_reason: "expired",
        disabled_until: "2026-06-18T10:00:00.000Z",
        id: "usr_expired_disable",
      },
    ];

    expect(authUserRows(users, now)).toEqual([
      {
        createdAt: "2026-06-18T09:00:00.000Z",
        disabledAt: "-",
        disabledReason: "-",
        disabledUntil: "-",
        id: "usr_active",
        status: "active",
      },
      {
        createdAt: "2026-06-17T09:00:00.000Z",
        disabledAt: "2026-06-18T10:00:00.000Z",
        disabledReason: "abuse",
        disabledUntil: "2026-06-19T10:00:00.000Z",
        id: "usr_disabled",
        status: "disabled",
      },
      {
        createdAt: "2026-06-16T09:00:00.000Z",
        disabledAt: "2026-06-17T10:00:00.000Z",
        disabledReason: "expired",
        disabledUntil: "2026-06-18T10:00:00.000Z",
        id: "usr_expired_disable",
        status: "active",
      },
    ]);
    expect(authUsersSummary(users, now)).toEqual({
      active: 2,
      disabled: 1,
      total: 3,
    });
  });

  test("formats auth session records from admin data", () => {
    const now = new Date("2026-06-18T12:00:00.000Z");
    const sessions = [
      {
        created_at: "2026-06-18T09:00:00.000Z",
        expires_at: "2026-06-18T13:00:00.000Z",
        id: "sess_active",
        revoked_at: null,
        user_id: "usr_active",
      },
      {
        created_at: "2026-06-18T09:00:00.000Z",
        expires_at: "2026-06-18T10:00:00.000Z",
        id: "sess_expired",
        revoked_at: null,
        user_id: "usr_expired",
      },
      {
        created_at: "2026-06-18T09:00:00.000Z",
        expires_at: "2026-06-18T13:00:00.000Z",
        id: "sess_revoked",
        revoked_at: "2026-06-18T11:00:00.000Z",
        user_id: "usr_revoked",
      },
    ];

    expect(authSessionRows(sessions, now).map((row) => row.status)).toEqual([
      "active",
      "expired",
      "revoked",
    ]);
    expect(authSessionsSummary(sessions, now)).toEqual({
      active: 1,
      expired: 1,
      revoked: 1,
      total: 3,
    });
  });

  test("reads console admin access from runtime config values", () => {
    const values = [
      {
        desired_value: {
          usr_admin: ["console.admin", "auth.users.read"],
          usr_viewer: ["auth.users.read"],
        },
        effective_value: {},
        key: CONSOLE_ADMIN_USER_SCOPES_CONFIG_KEY,
        pending_restart: true,
        source: "database",
        value: {},
      },
    ];

    expect(consoleAdminUserScopes(values)).toEqual({
      usr_admin: ["console.admin", "auth.users.read"],
      usr_viewer: ["auth.users.read"],
    });
    expect(consoleAdminAccessForUser("usr_admin", values)).toEqual({
      enabled: true,
      pendingRestart: true,
      scopes: ["console.admin", "auth.users.read"],
    });
    expect(consoleAdminAccessForUser("usr_viewer", values)).toEqual({
      enabled: false,
      pendingRestart: true,
      scopes: ["auth.users.read"],
    });
  });

  test("updates console admin access without dropping extra scopes", () => {
    expect(
      setConsoleAdminUserAccess(
        {
          usr_admin: ["custom.scope"],
          usr_other: ["console.admin"],
        },
        "usr_admin",
        true
      )
    ).toEqual({
      usr_admin: [
        "console.admin",
        "auth.users.read",
        "auth.users.manage",
        "auth.sessions.revoke",
        "custom.scope",
      ],
      usr_other: ["console.admin"],
    });

    expect(
      setConsoleAdminUserAccess(
        {
          usr_admin: ["console.admin", "auth.users.read"],
          usr_other: ["console.admin"],
        },
        "usr_admin",
        false
      )
    ).toEqual({
      usr_other: ["console.admin"],
    });
  });

  test("maps console access presets to exact scopes", () => {
    expect(DEFAULT_CONSOLE_ADMIN_SCOPES).toEqual([
      "console.admin",
      "auth.users.read",
      "auth.users.manage",
      "auth.sessions.revoke",
    ]);
    expect(
      CONSOLE_ACCESS_PRESETS.find((preset) => preset.id === "support")?.scopes
    ).toEqual(["console.admin", "auth.users.read"]);
    expect(
      CONSOLE_ACCESS_PRESETS.find((preset) => preset.id === "admin")?.scopes
    ).toEqual([
      "console.admin",
      "runtime.stories.read",
      "auth.users.read",
      "auth.users.manage",
      "auth.sessions.revoke",
      "identity.users.read",
    ]);
    expect(consoleAccessPresetId([])).toBe("none");
    expect(consoleAccessPresetId(["auth.users.read", "console.admin"])).toBe(
      "support"
    );
    expect(
      consoleAccessPresetId([
        "console.admin",
        "runtime.stories.read",
        "identity.users.read",
      ])
    ).toBe("operations");
    expect(
      consoleAccessPresetId(["console.admin", "custom.scope"])
    ).toBe("custom");

    expect(
      setConsoleUserScopes(
        { usr_admin: ["custom.scope"], usr_other: ["console.admin"] },
        "usr_admin",
        ["console.admin", "runtime.stories.read"]
      )
    ).toEqual({
      usr_admin: ["console.admin", "runtime.stories.read"],
      usr_other: ["console.admin"],
    });

    expect(
      setConsoleUserScopes({ usr_admin: ["console.admin"] }, "usr_admin", [])
    ).toEqual({});
  });
});
