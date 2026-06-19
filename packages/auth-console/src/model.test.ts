import { describe, expect, test } from "vitest";

import {
  authSessionRows,
  authSessionsSummary,
  authUserRows,
  authUsersSummary,
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
});
