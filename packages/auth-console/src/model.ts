import type {
  AuthSessionRecord,
  AuthUserRecord,
} from "./business-api";

export type AuthIdentityFilter = "all" | "anonymous" | "registered";
export type AuthUserStateFilter = "all" | "active" | "disabled";
export type AuthSessionStateFilter =
  | "all"
  | "active"
  | "expired"
  | "revoked";

export interface AuthUserRow {
  readonly createdAt: string;
  readonly disabledAt: string;
  readonly disabledReason: string;
  readonly disabledUntil: string;
  readonly id: string;
  readonly isAnonymous: boolean;
  readonly status: "active" | "disabled";
}

export interface AuthUsersSummary {
  active: number;
  anonymous: number;
  disabled: number;
  total: number;
}

export interface AuthSessionRow {
  readonly clientIp: string;
  readonly createdAt: string;
  readonly deviceId: string;
  readonly expiresAt: string;
  readonly id: string;
  readonly revokedAt: string;
  readonly status: "active" | "expired" | "revoked";
  readonly userAgent: string;
  readonly userId: string;
}

export interface AuthSessionsSummary {
  active: number;
  expired: number;
  revoked: number;
  total: number;
}

const fieldText = (value: unknown): string =>
  typeof value === "string" && value.length > 0 ? value : "-";

export const authUserRows = (
  records: readonly AuthUserRecord[],
  now = new Date()
): AuthUserRow[] =>
  records.map((record) => {
    const disabledAt = fieldText(record.disabled_at);
    const disabledUntil = fieldText(record.disabled_until);
    return {
      createdAt: fieldText(record.created_at),
      disabledAt,
      disabledReason: fieldText(record.disabled_reason),
      disabledUntil,
      id: fieldText(record.id),
      isAnonymous: record.is_anonymous,
      status: userStatus(disabledAt, disabledUntil, now),
    };
  });

export const authUsersSummary = (
  records: readonly AuthUserRecord[],
  now = new Date()
): AuthUsersSummary => {
  const summary: AuthUsersSummary = {
    active: 0,
    anonymous: 0,
    disabled: 0,
    total: 0,
  };
  for (const row of authUserRows(records, now)) {
    summary.total += 1;
    summary[row.status] += 1;
    if (row.isAnonymous) {
      summary.anonymous += 1;
    }
  }
  return summary;
};

export function filterAuthUserRows(
  rows: readonly AuthUserRow[],
  identity: AuthIdentityFilter,
  state: AuthUserStateFilter
): AuthUserRow[] {
  return rows.filter(
    (row) =>
      (identity === "all" ||
        (identity === "anonymous" ? row.isAnonymous : !row.isAnonymous)) &&
      (state === "all" || row.status === state)
  );
}

function userStatus(
  disabledAt: string,
  disabledUntil: string,
  now: Date
): AuthUserRow["status"] {
  if (disabledAt === "-") {
    return "active";
  }
  const untilMs = Date.parse(disabledUntil);
  return Number.isFinite(untilMs) && untilMs <= now.getTime()
    ? "active"
    : "disabled";
}

export const authSessionRows = (
  records: readonly AuthSessionRecord[],
  now = new Date()
): AuthSessionRow[] =>
  records.map((record) => {
    const revokedAt = fieldText(record.revoked_at);
    const expiresAt = fieldText(record.expires_at);
    return {
      clientIp: fieldText(record.client_ip),
      createdAt: fieldText(record.created_at),
      deviceId: fieldText(record.device_id),
      expiresAt,
      id: fieldText(record.id),
      revokedAt,
      status: sessionStatus(expiresAt, revokedAt, now),
      userAgent: fieldText(record.user_agent),
      userId: fieldText(record.user_id),
    };
  });

export const authSessionsSummary = (
  records: readonly AuthSessionRecord[],
  now = new Date()
): AuthSessionsSummary => {
  const summary: AuthSessionsSummary = {
    active: 0,
    expired: 0,
    revoked: 0,
    total: 0,
  };
  for (const row of authSessionRows(records, now)) {
    summary.total += 1;
    summary[row.status] += 1;
  }
  return summary;
};

export function filterAuthSessionRows(
  rows: readonly AuthSessionRow[],
  state: AuthSessionStateFilter
): AuthSessionRow[] {
  return state === "all" ? [...rows] : rows.filter((row) => row.status === state);
}

function sessionStatus(
  expiresAt: string,
  revokedAt: string,
  now: Date
): AuthSessionRow["status"] {
  if (revokedAt !== "-") {
    return "revoked";
  }
  const expiresMs = Date.parse(expiresAt);
  return Number.isFinite(expiresMs) && expiresMs <= now.getTime()
    ? "expired"
    : "active";
}

export function formatAuthTimestamp(value: string): string {
  if (value === "-") {
    return value;
  }
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    return value;
  }
  return new Date(timestamp)
    .toISOString()
    .replace("T", " ")
    .replace(".000Z", " UTC");
}
