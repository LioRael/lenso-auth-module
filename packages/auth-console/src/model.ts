import type { ConsoleAdminRecord } from "@lenso/runtime-console-api";

export const CONSOLE_ADMIN_USER_SCOPES_CONFIG_KEY =
  "auth.console_admin_user_scopes";
export const CONSOLE_ADMIN_USER_SCOPES_SERVICE = "*";
export const DEFAULT_CONSOLE_ADMIN_SCOPES = [
  "console.admin",
  "auth.users.read",
] as const;
export const CONSOLE_ACCESS_PRESETS = [
  {
    id: "support",
    label: "Support",
    scopes: ["console.admin", "auth.users.read"],
  },
  {
    id: "operations",
    label: "Operations",
    scopes: ["console.admin", "runtime.stories.read", "identity.users.read"],
  },
  {
    id: "admin",
    label: "Admin",
    scopes: [
      "console.admin",
      "runtime.stories.read",
      "auth.users.read",
      "identity.users.read",
    ],
  },
] as const;

export type AuthUserRow = {
  createdAt: string;
  disabledAt: string;
  disabledReason: string;
  disabledUntil: string;
  id: string;
  status: "active" | "disabled";
};

export type AuthUsersSummary = {
  active: number;
  disabled: number;
  total: number;
};

export type AuthSessionRow = {
  createdAt: string;
  expiresAt: string;
  id: string;
  revokedAt: string;
  status: "active" | "expired" | "revoked";
  userId: string;
};

export type AuthSessionsSummary = {
  active: number;
  expired: number;
  revoked: number;
  total: number;
};

export type ConsoleAdminAccess = {
  enabled: boolean;
  pendingRestart: boolean;
  scopes: string[];
};

export type ConsoleConfigValueLike = {
  desired_value: unknown;
  key: string;
  pending_restart: boolean;
};

const fieldText = (value: unknown): string =>
  typeof value === "string" && value.length > 0 ? value : "-";

export const authUserRows = (
  records: readonly ConsoleAdminRecord[],
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
      status: userStatus(disabledAt, disabledUntil, now),
    };
  });

export const authUsersSummary = (
  records: readonly ConsoleAdminRecord[],
  now = new Date()
): AuthUsersSummary => {
  const summary: AuthUsersSummary = { active: 0, disabled: 0, total: 0 };
  for (const row of authUserRows(records, now)) {
    summary.total += 1;
    summary[row.status] += 1;
  }
  return summary;
};

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
  records: readonly ConsoleAdminRecord[],
  now = new Date()
): AuthSessionRow[] =>
  records.map((record) => {
    const revokedAt = fieldText(record.revoked_at);
    const expiresAt = fieldText(record.expires_at);
    return {
      createdAt: fieldText(record.created_at),
      expiresAt,
      id: fieldText(record.id),
      revokedAt,
      status: sessionStatus(expiresAt, revokedAt, now),
      userId: fieldText(record.user_id),
    };
  });

export const authSessionsSummary = (
  records: readonly ConsoleAdminRecord[],
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

export function consoleAdminUserScopes(
  values: readonly ConsoleConfigValueLike[]
): Record<string, string[]> {
  const value = values.find(
    (item) => item.key === CONSOLE_ADMIN_USER_SCOPES_CONFIG_KEY
  );
  return normalizeConsoleAdminUserScopes(value?.desired_value);
}

export function consoleAdminAccessForUser(
  userId: string,
  values: readonly ConsoleConfigValueLike[]
): ConsoleAdminAccess {
  const value = values.find(
    (item) => item.key === CONSOLE_ADMIN_USER_SCOPES_CONFIG_KEY
  );
  const scopes =
    normalizeConsoleAdminUserScopes(value?.desired_value)[userId] ?? [];
  return {
    enabled: scopes.includes("console.admin"),
    pendingRestart: value?.pending_restart ?? false,
    scopes,
  };
}

export function setConsoleAdminUserAccess(
  current: Record<string, readonly string[]> | unknown,
  userId: string,
  enabled: boolean,
  scopes: readonly string[] = DEFAULT_CONSOLE_ADMIN_SCOPES
): Record<string, string[]> {
  const next = normalizeConsoleAdminUserScopes(current);
  if (enabled) {
    next[userId] = uniqueStrings([...scopes, ...(next[userId] ?? [])]);
  } else {
    delete next[userId];
  }
  return next;
}

export function setConsoleUserScopes(
  current: Record<string, readonly string[]> | unknown,
  userId: string,
  scopes: readonly string[]
): Record<string, string[]> {
  const next = normalizeConsoleAdminUserScopes(current);
  if (scopes.length > 0) {
    next[userId] = uniqueStrings(scopes);
  } else {
    delete next[userId];
  }
  return next;
}

export function consoleAccessPresetId(scopes: readonly string[]): string {
  if (scopes.length === 0) {
    return "none";
  }
  return (
    CONSOLE_ACCESS_PRESETS.find((preset) =>
      sameStringSet(scopes, preset.scopes)
    )?.id ?? "custom"
  );
}

function normalizeConsoleAdminUserScopes(
  value: unknown
): Record<string, string[]> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  const result: Record<string, string[]> = {};
  for (const [userId, scopes] of Object.entries(value)) {
    if (typeof userId === "string" && Array.isArray(scopes)) {
      const normalizedScopes = scopes.filter(
        (scope): scope is string =>
          typeof scope === "string" && scope.length > 0
      );
      if (normalizedScopes.length > 0) {
        result[userId] = uniqueStrings(normalizedScopes);
      }
    }
  }
  return result;
}

function uniqueStrings(values: readonly string[]) {
  return [...new Set(values)];
}

function sameStringSet(left: readonly string[], right: readonly string[]) {
  const leftSet = new Set(left);
  return (
    leftSet.size === right.length && right.every((item) => leftSet.has(item))
  );
}
