import { runtimeConsoleHostApi } from "@lenso/runtime-console-api";
import { useState } from "react";

import {
  authDeviceRows,
  authDevicesSummary,
  type AuthDeviceRow,
} from "./model";

const DEVICE_MODULE_NAME = "auth-device";
const DEVICE_ENTITY_NAME = "devices";

export const AuthDevicesPage = () => {
  const devicesQuery = runtimeConsoleHostApi.adminData.useRecords({
    entityName: DEVICE_ENTITY_NAME,
    moduleName: DEVICE_MODULE_NAME,
  });
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);
  const deviceRows = authDeviceRows(devicesQuery.data?.data ?? []);
  const summary = authDevicesSummary(devicesQuery.data?.data ?? []);
  const selectedDevice =
    deviceRows.find((device) => device.id === selectedDeviceId) ??
    deviceRows[0] ??
    null;

  return (
    <main className="grid h-full min-h-0 min-w-0 grid-rows-[auto_auto_minmax(0,1fr)] overflow-hidden bg-(--background) text-(--foreground)">
      <header className="border-b border-(--border-subtle) bg-(--surface) px-3 py-2">
        <div className="flex min-w-0 items-center gap-2">
          <h1 className="font-mono text-[13px] font-semibold">Devices</h1>
          <span className="ml-auto font-mono text-[10px] text-(--muted)">
            {deviceRows.length} records
          </span>
        </div>
      </header>

      <div className="grid border-b border-(--border-subtle) bg-(--surface) md:grid-cols-4">
        {[
          ["total", summary.total],
          ["seen", summary.seen],
          ["trusted", summary.trusted],
          ["primary", summary.primary],
        ].map(([label, value]) => (
          <div
            className="grid grid-cols-[minmax(0,1fr)_auto] border-r border-(--border-subtle) px-3 py-2 font-mono text-[10px] last:border-r-0"
            key={label}
          >
            <span className="text-(--muted)">{label}</span>
            <span className="text-[13px] font-semibold text-(--foreground)">
              {value}
            </span>
          </div>
        ))}
      </div>

      <div className="grid min-h-0 min-w-0 grid-cols-[minmax(0,1fr)_clamp(280px,28vw,400px)] overflow-hidden">
        <section className="grid min-h-0 min-w-0 grid-rows-[auto_minmax(0,1fr)] overflow-hidden border-r border-(--border-subtle)">
          <SectionHeader meta={`${deviceRows.length} records`} title="Devices" />
          <AuthDevicesTable
            error={devicesQuery.error}
            isError={devicesQuery.isError}
            isPending={devicesQuery.isPending}
            onSelect={setSelectedDeviceId}
            rows={deviceRows}
            selectedDevice={selectedDevice}
          />
        </section>

        <aside className="grid min-h-0 min-w-0 grid-rows-[auto_minmax(0,1fr)] overflow-hidden bg-(--sidebar)">
          <SectionHeader
            meta={selectedDevice ? selectedDevice.status : "no selection"}
            title={selectedDevice?.id ?? "Device"}
          />
          {selectedDevice ? (
            <div className="min-h-0 overflow-auto">
              <Metric label="user" value={selectedDevice.userId} />
              <Metric label="created" value={selectedDevice.createdAt} />
              <Metric label="updated" value={selectedDevice.updatedAt} />
              <Metric label="trusted" value={selectedDevice.trustedAt} />
              <Metric label="primary" value={selectedDevice.primaryAt} />
              <Metric label="last ip" value={selectedDevice.lastSeenIp} />
              <Metric
                label="user agent"
                value={selectedDevice.lastSeenUserAgent}
              />
            </div>
          ) : (
            <PanelMessage value="Select a device" />
          )}
        </aside>
      </div>
    </main>
  );
};

const AuthDevicesTable = ({
  error,
  isError,
  isPending,
  onSelect,
  rows,
  selectedDevice,
}: {
  error: unknown;
  isError: boolean;
  isPending: boolean;
  onSelect: (deviceId: string) => void;
  rows: AuthDeviceRow[];
  selectedDevice: AuthDeviceRow | null;
}) => {
  if (isError) {
    return (
      <PanelMessage
        tone="error"
        value={String((error as Error | undefined)?.message)}
      />
    );
  }
  if (isPending) {
    return <PanelMessage value="Loading auth devices" />;
  }
  if (rows.length === 0) {
    return <PanelMessage value="No auth devices found" />;
  }

  return (
    <div className="min-h-0 overflow-auto">
      <div className="grid min-w-260 grid-cols-[minmax(220px,1fr)_minmax(180px,0.8fr)_170px_170px_92px] border-b border-(--border-subtle) bg-(--surface) px-3 py-1.5 font-mono text-[10px] text-(--muted)">
        <span>Device</span>
        <span>User</span>
        <span>Updated</span>
        <span>Last IP</span>
        <span>Status</span>
      </div>
      {rows.map((device) => {
        const selected = selectedDevice?.id === device.id;
        return (
          <button
            aria-pressed={selected}
            className={[
              "grid min-h-11 w-full min-w-260 grid-cols-[minmax(220px,1fr)_minmax(180px,0.8fr)_170px_170px_92px] items-center gap-0 border-b border-(--border-subtle) px-3 py-2 text-left font-mono text-[11px] transition",
              selected ? "native-selection" : "hover:bg-(--bg-row-hover)",
            ].join(" ")}
            key={device.id}
            onClick={() => onSelect(device.id)}
            type="button"
          >
            <span className="truncate text-(--foreground)">{device.id}</span>
            <span className="truncate text-(--muted)">{device.userId}</span>
            <span className="truncate text-(--muted)">{device.updatedAt}</span>
            <span className="truncate text-(--muted)">
              {device.lastSeenIp}
            </span>
            <StatusPill status={device.status} />
          </button>
        );
      })}
    </div>
  );
};

function SectionHeader({ meta, title }: { meta?: string; title: string }) {
  return (
    <div className="flex min-w-0 items-center gap-2 border-b border-(--border-subtle) bg-(--surface) px-3 py-2">
      <h2 className="truncate font-mono text-[11px] font-semibold text-(--foreground)">
        {title}
      </h2>
      {meta ? (
        <span className="ml-auto truncate font-mono text-[10px] text-(--muted)">
          {meta}
        </span>
      ) : null}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid grid-cols-[112px_minmax(0,1fr)] gap-2 border-b border-(--border-subtle) bg-(--surface) px-3 py-2 font-mono text-[10px]">
      <span className="text-(--muted)">{label}</span>
      <span className="truncate text-(--foreground)" title={value}>
        {value}
      </span>
    </div>
  );
}

function StatusPill({ status }: { status: AuthDeviceRow["status"] }) {
  const tone =
    status === "primary"
      ? "bg-[var(--tone-success-bg)] text-(--tone-success-fg) border-[var(--tone-success-border)]"
      : status === "trusted"
        ? "bg-[var(--tone-info-bg)] text-(--tone-info-fg) border-[var(--tone-info-border)]"
        : "bg-[var(--tone-muted-bg)] text-(--tone-muted-fg) border-[var(--tone-muted-border)]";
  return (
    <span
      className={`inline-flex h-5 w-fit max-w-full items-center border px-1.5 font-mono text-[10px] ${tone}`}
    >
      {status}
    </span>
  );
}

function PanelMessage({
  tone = "muted",
  value,
}: {
  tone?: "error" | "muted";
  value: string;
}) {
  return (
    <div
      className={[
        "p-3 font-mono text-[11px]",
        tone === "error" ? "text-(--error)" : "text-(--muted)",
      ].join(" ")}
    >
      {value}
    </div>
  );
}
