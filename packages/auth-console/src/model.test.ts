import { describe, expect, test } from "vitest";

import {
  authSessionRows,
  authSessionsSummary,
  authUserRows,
  authUsersSummary,
  filterAuthSessionRows,
  filterAuthUserRows,
  formatAuthTimestamp,
} from "./model";

describe("Auth Console model", () => {
  test("formats and filters Auth users", () => {
    const now = new Date("2026-06-18T12:00:00.000Z");
    const users = [
      {
        created_at: "2026-06-18T09:00:00.000Z",
        disabled_at: null,
        disabled_reason: null,
        disabled_until: null,
        id: "usr_active",
        is_anonymous: false,
      },
      {
        created_at: "2026-06-17T09:00:00.000Z",
        disabled_at: "2026-06-18T10:00:00.000Z",
        disabled_reason: "review",
        disabled_until: "2026-06-19T10:00:00.000Z",
        id: "usr_disabled",
        is_anonymous: true,
      },
      {
        created_at: "2026-06-16T09:00:00.000Z",
        disabled_at: "2026-06-17T10:00:00.000Z",
        disabled_reason: "expired",
        disabled_until: "2026-06-18T10:00:00.000Z",
        id: "usr_expired_disable",
        is_anonymous: false,
      },
    ];

    const rows = authUserRows(users, now);
    expect(rows.map(({ id, isAnonymous, status }) => ({
      id,
      isAnonymous,
      status,
    }))).toEqual([
      { id: "usr_active", isAnonymous: false, status: "active" },
      { id: "usr_disabled", isAnonymous: true, status: "disabled" },
      {
        id: "usr_expired_disable",
        isAnonymous: false,
        status: "active",
      },
    ]);
    expect(authUsersSummary(users, now)).toEqual({
      active: 2,
      anonymous: 1,
      disabled: 1,
      total: 3,
    });
    expect(filterAuthUserRows(rows, "anonymous", "disabled")).toEqual([
      rows[1],
    ]);
  });

  test("formats and filters Auth sessions", () => {
    const now = new Date("2026-06-18T12:00:00.000Z");
    const sessions = [
      {
        client_ip: "203.0.113.7",
        created_at: "2026-06-18T09:00:00.000Z",
        device_id: "device_1",
        expires_at: "2026-06-18T13:00:00.000Z",
        id: "sess_active",
        revoked_at: null,
        user_agent: "LensoTest/1.0",
        user_id: "usr_active",
      },
      {
        client_ip: null,
        created_at: "2026-06-18T09:00:00.000Z",
        device_id: null,
        expires_at: "2026-06-18T10:00:00.000Z",
        id: "sess_expired",
        revoked_at: null,
        user_agent: null,
        user_id: "usr_expired",
      },
      {
        client_ip: null,
        created_at: "2026-06-18T09:00:00.000Z",
        device_id: null,
        expires_at: "2026-06-18T13:00:00.000Z",
        id: "sess_revoked",
        revoked_at: "2026-06-18T11:00:00.000Z",
        user_agent: null,
        user_id: "usr_revoked",
      },
    ];

    const rows = authSessionRows(sessions, now);
    expect(rows.map((row) => row.status)).toEqual([
      "active",
      "expired",
      "revoked",
    ]);
    expect(rows[0]).toMatchObject({
      clientIp: "203.0.113.7",
      deviceId: "device_1",
      userAgent: "LensoTest/1.0",
    });
    expect(authSessionsSummary(sessions, now)).toEqual({
      active: 1,
      expired: 1,
      revoked: 1,
      total: 3,
    });
    expect(filterAuthSessionRows(rows, "revoked")).toEqual([rows[2]]);
  });

  test("formats RFC3339 timestamps for the compact directory", () => {
    expect(formatAuthTimestamp("2026-06-18T09:00:00.000Z")).toBe(
      "2026-06-18 09:00:00 UTC"
    );
    expect(formatAuthTimestamp("-")).toBe("-");
  });
});
