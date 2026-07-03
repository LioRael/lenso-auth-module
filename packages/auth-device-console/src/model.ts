import type { ConsoleAdminRecord } from "@lenso/runtime-console-api";

export type AuthDeviceRow = {
  createdAt: string;
  id: string;
  lastSeenIp: string;
  lastSeenUserAgent: string;
  primaryAt: string;
  status: "primary" | "trusted" | "seen";
  trustedAt: string;
  updatedAt: string;
  userId: string;
};

export type AuthDevicesSummary = {
  primary: number;
  seen: number;
  total: number;
  trusted: number;
};

const fieldText = (value: unknown): string =>
  typeof value === "string" && value.length > 0 ? value : "-";

export const authDeviceRows = (
  records: readonly ConsoleAdminRecord[]
): AuthDeviceRow[] =>
  records.map((record) => {
    const primaryAt = fieldText(record.primary_at);
    const trustedAt = fieldText(record.trusted_at);
    const lastSeenIp = fieldText(record.last_seen_ip);
    const lastSeenUserAgent = fieldText(record.last_seen_user_agent);
    return {
      createdAt: fieldText(record.created_at),
      id: fieldText(record.id),
      lastSeenIp,
      lastSeenUserAgent,
      primaryAt,
      status: deviceStatus(primaryAt, trustedAt),
      trustedAt,
      updatedAt: fieldText(record.updated_at),
      userId: fieldText(record.user_id),
    };
  });

export const authDevicesSummary = (
  records: readonly ConsoleAdminRecord[]
): AuthDevicesSummary => {
  const summary: AuthDevicesSummary = {
    primary: 0,
    seen: 0,
    total: 0,
    trusted: 0,
  };
  for (const row of authDeviceRows(records)) {
    summary.total += 1;
    summary.seen += row.lastSeenIp !== "-" || row.lastSeenUserAgent !== "-" ? 1 : 0;
    if (row.trustedAt !== "-") {
      summary.trusted += 1;
    }
    if (row.primaryAt !== "-") {
      summary.primary += 1;
    }
  }
  return summary;
};

function deviceStatus(
  primaryAt: string,
  trustedAt: string
): AuthDeviceRow["status"] {
  if (primaryAt !== "-") {
    return "primary";
  }
  return trustedAt !== "-" ? "trusted" : "seen";
}
