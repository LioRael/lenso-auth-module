import { describe, expect, test } from "vitest";

import { authDeviceRows, authDevicesSummary } from "./model";

describe("auth device console model", () => {
  test("formats auth device records from admin data", () => {
    const records = [
      {
        created_at: "2026-07-03T08:00:00.000Z",
        id: "device_primary",
        last_seen_ip: "203.0.113.10",
        last_seen_user_agent: "Safari",
        primary_at: "2026-07-03T09:00:00.000Z",
        trusted_at: "2026-07-03T08:30:00.000Z",
        updated_at: "2026-07-03T09:30:00.000Z",
        user_id: "user_1",
      },
      {
        created_at: "2026-07-02T08:00:00.000Z",
        id: "device_seen",
        last_seen_ip: null,
        last_seen_user_agent: null,
        primary_at: null,
        trusted_at: null,
        updated_at: "2026-07-02T09:30:00.000Z",
        user_id: "user_2",
      },
    ];

    expect(authDeviceRows(records)).toEqual([
      {
        createdAt: "2026-07-03T08:00:00.000Z",
        id: "device_primary",
        lastSeenIp: "203.0.113.10",
        lastSeenUserAgent: "Safari",
        primaryAt: "2026-07-03T09:00:00.000Z",
        status: "primary",
        trustedAt: "2026-07-03T08:30:00.000Z",
        updatedAt: "2026-07-03T09:30:00.000Z",
        userId: "user_1",
      },
      {
        createdAt: "2026-07-02T08:00:00.000Z",
        id: "device_seen",
        lastSeenIp: "-",
        lastSeenUserAgent: "-",
        primaryAt: "-",
        status: "seen",
        trustedAt: "-",
        updatedAt: "2026-07-02T09:30:00.000Z",
        userId: "user_2",
      },
    ]);
    expect(authDevicesSummary(records)).toEqual({
      primary: 1,
      seen: 1,
      total: 2,
      trusted: 1,
    });
  });
});
