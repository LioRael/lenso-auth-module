import {
  ConsolePage,
  DataGrid,
  DataRow,
  FilterSelect,
  InlineStatus,
  Inspector,
  KeyValueList,
  PaneHeader,
  SplitView,
  StateView,
  SurfaceRoot,
  TableHeader,
  pageStyles,
  useConsoleClient,
  type SemanticTone,
} from "@lenso/console-ui";
import * as stylex from "@stylexjs/stylex";
import { useEffect, useMemo, useState, type ReactNode } from "react";

import { listAuthDevices, type AuthDevicePage } from "./business-api";
import {
  authDeviceRows,
  type AuthDeviceRow,
} from "./model";

type AuthDeviceStateFilter = "all" | AuthDeviceRow["status"];

const styles = stylex.create({
  filterChevron: {
    display: "inline-block",
    fontSize: 10,
    lineHeight: 1,
    transform: "translateY(-1px)",
  },
  filters: { flexWrap: "wrap" },
  state: { backgroundColor: "var(--lenso-token-canvas, #000000)" },
});

export function AuthDevicesPage() {
  const client = useConsoleClient();
  const devicesQuery = useAuthDevices(client);
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);
  const [stateFilter, setStateFilter] = useState<AuthDeviceStateFilter>("all");
  const deviceRows = useMemo(
    () => authDeviceRows(devicesQuery.data?.records ?? []),
    [devicesQuery.data?.records]
  );
  const filteredRows = useMemo(
    () =>
      stateFilter === "all"
        ? deviceRows
        : deviceRows.filter((device) => device.status === stateFilter),
    [deviceRows, stateFilter]
  );
  const selectedDevice =
    filteredRows.find((device) => device.id === selectedDeviceId) ??
    filteredRows[0] ??
    deviceRows.find((device) => device.id === selectedDeviceId) ??
    null;

  return (
    <SurfaceRoot moduleId="lenso/auth-device" surfaceId="devices">
      <ConsolePage data-page="auth-devices-page">
        <ConsolePage.Header>
          <ConsolePage.Heading>
            <ConsolePage.Title>Devices</ConsolePage.Title>
            <ConsolePage.Description>
              Auth device bindings, trust state, and the latest client evidence
              owned by Auth Device.
            </ConsolePage.Description>
          </ConsolePage.Heading>
          <ConsolePage.Actions>
            Schema-admin surface  ·  live runtime data
          </ConsolePage.Actions>
        </ConsolePage.Header>

        <ConsolePage.Body data-page-slot="auth-devices-page__body">
          <div
            {...stylex.props(pageStyles.pageFilters, styles.filters)}
            data-page-slot="auth-devices-page__filters"
          >
            <DeviceFilter ariaLabel="Device view" value="all">
              <option value="all">All devices</option>
            </DeviceFilter>
            <DeviceFilter
              ariaLabel="Trust state"
              onChange={(value) =>
                setStateFilter(value as AuthDeviceStateFilter)
              }
              value={stateFilter}
            >
              <option value="all">Any trust</option>
              <option value="primary">Primary</option>
              <option value="trusted">Trusted</option>
              <option value="seen">Seen</option>
            </DeviceFilter>
            <DeviceFilter ariaLabel="Client evidence" value="any">
              <option value="any">Any evidence</option>
            </DeviceFilter>
          </div>

          {devicesQuery.isPending ? (
            <DeviceState
              description="Reading Auth Device records from the selected Managed Service."
              title="Loading devices"
            />
          ) : devicesQuery.isError ? (
            <DeviceState
              description={errorMessage(devicesQuery.error)}
              title="Devices could not be loaded"
            />
          ) : (
            <SplitView
              data-page-slot="auth-devices-page__workspace"
              inspectorWidth={376}
            >
              <SplitView.Main>
                <PaneHeader
                  meta={`${filteredRows.length} of ${deviceRows.length}`}
                  title="Device registry"
                />
                <DataGrid>
                  <TableHeader
                    columns={["Device", "User", "Updated", "State"]}
                  />
                  {filteredRows.length === 0 ? (
                    <DeviceState
                      description="Adjust the trust filter to see other Auth Device records."
                      title="No devices match this filter"
                    />
                  ) : (
                    filteredRows.map((device) => (
                      <DataRow
                        cells={[
                          device.userId,
                          formatTimestamp(device.updatedAt),
                          <DeviceStatus
                            key={`${device.id}-state`}
                            status={device.status}
                          />,
                        ]}
                        interactive
                        key={device.id}
                        onActivate={() => setSelectedDeviceId(device.id)}
                        primary={device.id}
                        secondary={
                          device.lastSeenIp === "-"
                            ? "No client address"
                            : device.lastSeenIp
                        }
                        selected={selectedDevice?.id === device.id}
                      />
                    ))
                  )}
                </DataGrid>
              </SplitView.Main>
              <SplitView.Inspector>
                <DeviceInspector device={selectedDevice} />
              </SplitView.Inspector>
            </SplitView>
          )}
        </ConsolePage.Body>
      </ConsolePage>
    </SurfaceRoot>
  );
}

function DeviceInspector({ device }: { device: AuthDeviceRow | null }) {
  if (!device) {
    return (
      <DeviceState
        description="Choose a device from the registry to inspect it."
        title="No device selected"
      />
    );
  }

  return (
    <Inspector
      status={<DeviceStatus status={device.status} />}
      subtitle={device.userId}
      title={device.id}
    >
      <Inspector.Section title="Identity">
        <KeyValueList>
          <KeyValueList.Row label="User" value={device.userId} />
          <KeyValueList.Row
            label="Created"
            value={formatTimestamp(device.createdAt)}
          />
          <KeyValueList.Row
            label="Updated"
            value={formatTimestamp(device.updatedAt)}
          />
        </KeyValueList>
      </Inspector.Section>
      <Inspector.Section title="Trust state">
        <KeyValueList>
          <KeyValueList.Row label="State" value={titleCase(device.status)} />
          <KeyValueList.Row
            label="Trusted"
            value={formatTimestamp(device.trustedAt)}
          />
          <KeyValueList.Row
            label="Primary"
            value={formatTimestamp(device.primaryAt)}
          />
        </KeyValueList>
      </Inspector.Section>
      <Inspector.Section title="Client evidence">
        <KeyValueList>
          <KeyValueList.Row label="Last IP" value={device.lastSeenIp} />
          <KeyValueList.Row
            label="User agent"
            value={device.lastSeenUserAgent}
          />
        </KeyValueList>
      </Inspector.Section>
      <Inspector.Section title="Surface">
        <KeyValueList>
          <KeyValueList.Row label="Workspace" value="Auth" />
          <KeyValueList.Row label="Group" value="Directory" />
          <KeyValueList.Row label="Surface" value="Devices" />
        </KeyValueList>
      </Inspector.Section>
    </Inspector>
  );
}

function DeviceFilter({
  ariaLabel,
  children,
  onChange,
  value,
}: {
  ariaLabel: string;
  children: ReactNode;
  onChange?: (value: string) => void;
  value: string;
}) {
  return (
    <FilterSelect
      aria-label={ariaLabel}
      icon={<span {...stylex.props(styles.filterChevron)}>⌄</span>}
      onChange={(event) => onChange?.(event.currentTarget.value)}
      value={value}
    >
      {children}
    </FilterSelect>
  );
}

function DeviceStatus({ status }: { status: AuthDeviceRow["status"] }) {
  const tone: SemanticTone =
    status === "primary" ? "success" : status === "trusted" ? "info" : "neutral";
  return <InlineStatus tone={tone}>{titleCase(status)}</InlineStatus>;
}

function DeviceState({
  description,
  title,
}: {
  description: string;
  title: string;
}) {
  return (
    <StateView description={description} stylex={styles.state} title={title} />
  );
}

function useAuthDevices(client: ReturnType<typeof useConsoleClient>): {
  data?: AuthDevicePage;
  error: unknown;
  isError: boolean;
  isPending: boolean;
} {
  const [state, setState] = useState<{
    data?: AuthDevicePage;
    error: unknown;
    isError: boolean;
    isPending: boolean;
  }>({ error: null, isError: false, isPending: true });
  const contextKey = useMemo(
    () =>
      JSON.stringify([
        client.identity,
        client.managedServiceContext.systemId,
        client.managedServiceContext.serviceId,
      ]),
    [client]
  );

  useEffect(() => {
    let active = true;
    setState({ error: null, isError: false, isPending: true });
    void listAuthDevices(client, { limit: 200 })
      .then((data) => {
        if (active) {
          setState({ data, error: null, isError: false, isPending: false });
        }
      })
      .catch((error: unknown) => {
        if (active) {
          setState({ error, isError: true, isPending: false });
        }
      });
    return () => {
      active = false;
    };
  }, [client, contextKey]);

  return state;
}

function formatTimestamp(value: string): string {
  if (value === "-") {
    return value;
  }
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp)
    ? new Date(timestamp).toISOString().replace("T", " ").replace(".000Z", " UTC")
    : value;
}

function titleCase(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
