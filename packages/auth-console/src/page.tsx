import {
  Button,
  ConsolePage,
  DataGrid,
  DataRow,
  Field,
  FilterSelect,
  InlineStatus,
  Input,
  Inspector,
  KeyValueList,
  PaneHeader,
  SplitView,
  StateView,
  SurfaceRoot,
  TableHeader,
  Tabs,
  consoleHostApi,
  pageStyles,
  useConsoleClient,
  type ConsoleResolvedOperationContribution,
  type SemanticTone,
} from "@lenso/console-ui";
import * as stylex from "@stylexjs/stylex";
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";

import {
  createAuthBusinessApi,
} from "./business-api";
import {
  authSessionRows,
  authUserRows,
  filterAuthSessionRows,
  filterAuthUserRows,
  formatAuthTimestamp,
  type AuthIdentityFilter,
  type AuthSessionExpiryFilter,
  type AuthSessionRow,
  type AuthSessionStateFilter,
  type AuthUserRow,
  type AuthUserStateFilter,
} from "./model";

const AUTH_USERS_DETAIL_ACTIONS_SLOT = "auth.users.detail.actions";
const AUTH_USERS_MANAGE = "auth.users.manage";
const AUTH_SESSIONS_REVOKE = "auth.sessions.revoke";

type InspectorTab = "actions" | "details" | "sessions";
type SessionInspectorTab = "details" | "evidence";
type UserMutation =
  | { readonly kind: "disable"; readonly reason?: string; readonly until?: string }
  | { readonly kind: "enable" };

type UserActionRegistryEntry = {
  readonly available: boolean;
  readonly effect: string;
  readonly id: string;
  readonly kind: "Core" | "Extension";
  readonly label: string;
  readonly operationId: string;
  readonly owner: string;
};

const styles = stylex.create({
  actionForm: {
    display: "grid",
    gap: 10,
    paddingBlock: 4,
  },
  actionStack: {
    display: "flex",
    flexDirection: "column",
    gap: 10,
  },
  feedback: {
    color: "var(--lenso-token-toneErrorForeground, #ff8589)",
    fontFamily: 'var(--lenso-token-fontCode, "Roboto Mono", monospace)',
    fontSize: 10,
    lineHeight: "14px",
    margin: 0,
    overflowWrap: "anywhere",
  },
  filterChevron: {
    display: "inline-block",
    fontSize: 10,
    lineHeight: 1,
    transform: "translateY(-1px)",
  },
  filters: {
    flexWrap: "wrap",
  },
  inspectorLines: {
    display: "grid",
    gap: 5,
  },
  mono: {
    fontFamily: 'var(--lenso-token-fontCode, "Roboto Mono", monospace)',
  },
  state: {
    backgroundColor: "var(--lenso-token-canvas, #000000)",
  },
  tabs: {
    marginBlockStart: 2,
  },
});

export function AuthUsersPage() {
  const client = useConsoleClient();
  const api = useMemo(() => createAuthBusinessApi(client), [client]);
  const loadUsers = useCallback(() => api.listUsers({ limit: 200 }), [api]);
  const usersQuery = useAsyncQuery(loadUsers);
  const [identityFilter, setIdentityFilter] =
    useState<AuthIdentityFilter>("all");
  const [stateFilter, setStateFilter] = useState<AuthUserStateFilter>("all");
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [selectedActionId, setSelectedActionId] = useState<string | null>(null);
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>("details");
  const records = usersQuery.data?.records;
  const rows = useMemo(() => authUserRows(records ?? []), [records]);
  const filteredRows = useMemo(
    () => filterAuthUserRows(rows, identityFilter, stateFilter),
    [identityFilter, rows, stateFilter]
  );
  const selectedUser =
    filteredRows.find((user) => user.id === selectedUserId) ??
    filteredRows[0] ??
    rows.find((user) => user.id === selectedUserId) ??
    null;
  const detailActions = consoleHostApi.contributions.useSlot(
    AUTH_USERS_DETAIL_ACTIONS_SLOT,
    { selected_user: selectedUser ?? {} }
  );
  const canManage = client.capabilities.has(AUTH_USERS_MANAGE);
  const actionRegistry = userActionRegistry(
    selectedUser,
    canManage,
    detailActions,
    client.capabilities
  );
  const selectedAction =
    actionRegistry.find((action) => action.id === selectedActionId) ??
    actionRegistry[0] ??
    null;
  const isActionsView = inspectorTab === "actions";
  const executeUserMutation = useCallback(
    async (mutation: UserMutation) => {
      if (!selectedUser) {
        return;
      }
      if (mutation.kind === "enable") {
        await api.enableUser(selectedUser.id);
        return;
      }
      await api.disableUser(selectedUser.id, {
        ...(mutation.reason ? { reason: mutation.reason } : {}),
        ...(mutation.until ? { disabled_until: mutation.until } : {}),
      });
    },
    [api, selectedUser]
  );
  const userMutation = useAsyncMutation(
    executeUserMutation,
    usersQuery.refetch
  );

  const disableUser = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedUser || !canManage) {
      return;
    }
    const form = new FormData(event.currentTarget);
    const reason = String(form.get("reason") ?? "").trim();
    const untilInput = String(form.get("disabled_until") ?? "").trim();
    const until = untilInput ? new Date(untilInput).toISOString() : undefined;
    userMutation.mutate({
      kind: "disable",
      ...(reason ? { reason } : {}),
      ...(until ? { until } : {}),
    });
  };

  return (
    <SurfaceRoot moduleId="lenso/auth" surfaceId="users">
      <ConsolePage data-page="auth-users-page">
        <ConsolePage.Header>
          <ConsolePage.Heading>
            <ConsolePage.Title>
              {isActionsView ? "User actions" : "Users"}
            </ConsolePage.Title>
            <ConsolePage.Description>
              {isActionsView
                ? "Core Auth operations and module-contributed actions for the selected identity."
                : "User identities registered by Auth, with actions contributed by password and phone modules."}
            </ConsolePage.Description>
          </ConsolePage.Heading>
          <ConsolePage.Actions>
            {isActionsView
              ? `Selected user · ${selectedUser?.id ?? "none"}`
              : "Schema-admin surface  ·  live runtime data"}
          </ConsolePage.Actions>
        </ConsolePage.Header>

        <ConsolePage.Body data-page-slot="auth-users-page__body">
          <div
            {...stylex.props(pageStyles.pageFilters, styles.filters)}
            data-page-slot="auth-users-page__filters"
          >
            {isActionsView ? (
              <>
                <DirectoryFilter ariaLabel="Action view" value="all">
                  <option value="all">All actions</option>
                </DirectoryFilter>
                <DirectoryFilter ariaLabel="Action owner" value="all">
                  <option value="all">Core + extensions</option>
                </DirectoryFilter>
                <DirectoryFilter ariaLabel="Action state" value="available">
                  <option value="available">Available now</option>
                </DirectoryFilter>
              </>
            ) : (
              <>
                <DirectoryFilter ariaLabel="User view" value="all">
                  <option value="all">All users</option>
                </DirectoryFilter>
                <DirectoryFilter
                  ariaLabel="Identity type"
                  onChange={(value) =>
                    setIdentityFilter(value as AuthIdentityFilter)
                  }
                  value={identityFilter}
                >
                  <option value="all">Any identity</option>
                  <option value="registered">Registered</option>
                  <option value="anonymous">Anonymous</option>
                </DirectoryFilter>
                <DirectoryFilter
                  ariaLabel="User state"
                  onChange={(value) =>
                    setStateFilter(value as AuthUserStateFilter)
                  }
                  value={stateFilter}
                >
                  <option value="all">Any state</option>
                  <option value="active">Active</option>
                  <option value="disabled">Disabled</option>
                </DirectoryFilter>
              </>
            )}
          </div>

          {usersQuery.isPending ? (
            <DirectoryState
              description="Reading users from the selected Managed Service."
              title="Loading Auth users"
            />
          ) : usersQuery.isError ? (
            <DirectoryState
              description={errorMessage(usersQuery.error)}
              title="Auth users could not be loaded"
            />
          ) : (
            <SplitView
              data-page-slot="auth-users-page__workspace"
              inspectorWidth={376}
            >
              <SplitView.Main>
                <PaneHeader
                  meta={
                    isActionsView
                      ? `${actionRegistry.length} registered`
                      : "Latest records"
                  }
                  title={isActionsView ? "Action registry" : "User directory"}
                />
                <DataGrid>
                  {isActionsView ? (
                    <UserActionRegistry
                      actions={actionRegistry}
                      onSelect={setSelectedActionId}
                      selectedAction={selectedAction}
                    />
                  ) : (
                    <>
                      <TableHeader
                        columns={["User", "Anonymous", "Created", "State"]}
                      />
                      {filteredRows.length === 0 ? (
                        <DirectoryState
                          description="Adjust the identity or state filters to see other users."
                          title="No users match these filters"
                        />
                      ) : (
                        filteredRows.map((user) => (
                          <DataRow
                            cells={[
                              user.isAnonymous ? "Yes" : "No",
                              formatAuthTimestamp(user.createdAt),
                              <InlineStatus
                                key={`${user.id}-state`}
                                tone={statusTone(user.status)}
                              >
                                {titleCase(user.status)}
                              </InlineStatus>,
                            ]}
                            interactive
                            key={user.id}
                            onActivate={() => setSelectedUserId(user.id)}
                            primary={user.id}
                            secondary={
                              user.isAnonymous
                                ? "Anonymous identity"
                                : "Registered identity"
                            }
                            selected={selectedUser?.id === user.id}
                          />
                        ))
                      )}
                    </>
                  )}
                </DataGrid>
              </SplitView.Main>
              <SplitView.Inspector>
                <UserInspector
                  actionRegistry={actionRegistry}
                  canManage={canManage}
                  extensionActions={detailActions}
                  inspectorTab={inspectorTab}
                  mutation={userMutation}
                  onChangeTab={setInspectorTab}
                  onDisable={disableUser}
                  onEnable={() => userMutation.mutate({ kind: "enable" })}
                  selectedAction={selectedAction}
                  user={selectedUser}
                />
              </SplitView.Inspector>
            </SplitView>
          )}
        </ConsolePage.Body>
      </ConsolePage>
    </SurfaceRoot>
  );
}

function UserActionRegistry({
  actions,
  onSelect,
  selectedAction,
}: {
  actions: readonly UserActionRegistryEntry[];
  onSelect: (actionId: string) => void;
  selectedAction: UserActionRegistryEntry | null;
}) {
  return (
    <>
      <TableHeader columns={["Action", "Kind", "Effect", "State"]} />
      {actions.map((action) => (
        <DataRow
          cells={[
            action.kind,
            action.effect,
            <InlineStatus
              key={`${action.id}-state`}
              tone={action.available ? "success" : "neutral"}
            >
              {action.available ? "Available" : "Unavailable"}
            </InlineStatus>,
          ]}
          interactive
          key={action.id}
          onActivate={() => onSelect(action.id)}
          primary={action.label}
          secondary={action.owner}
          selected={selectedAction?.id === action.id}
        />
      ))}
    </>
  );
}

export function AuthSessionsPage() {
  const client = useConsoleClient();
  const api = useMemo(() => createAuthBusinessApi(client), [client]);
  const loadSessions = useCallback(
    () => api.listSessions({ limit: 200 }),
    [api]
  );
  const sessionsQuery = useAsyncQuery(loadSessions);
  const [stateFilter, setStateFilter] =
    useState<AuthSessionStateFilter>("all");
  const [expiryFilter, setExpiryFilter] =
    useState<AuthSessionExpiryFilter>("all");
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(
    null
  );
  const records = sessionsQuery.data?.records;
  const rows = useMemo(() => authSessionRows(records ?? []), [records]);
  const filteredRows = useMemo(
    () => filterAuthSessionRows(rows, stateFilter, expiryFilter),
    [expiryFilter, rows, stateFilter]
  );
  const selectedSession =
    filteredRows.find((session) => session.id === selectedSessionId) ??
    filteredRows[0] ??
    rows.find((session) => session.id === selectedSessionId) ??
    null;
  const canRevoke = client.capabilities.has(AUTH_SESSIONS_REVOKE);
  const revokeSelectedSession = useCallback(async () => {
    if (selectedSession) {
      await api.revokeSession(selectedSession.id);
    }
  }, [api, selectedSession]);
  const revokeSession = useAsyncMutation(
    revokeSelectedSession,
    sessionsQuery.refetch
  );

  return (
    <SurfaceRoot moduleId="lenso/auth" surfaceId="sessions">
      <ConsolePage data-page="auth-sessions-page">
        <ConsolePage.Header>
          <ConsolePage.Heading>
            <ConsolePage.Title>Sessions</ConsolePage.Title>
            <ConsolePage.Description>
              Authentication sessions, expiry state, and revocation evidence
              owned by Auth.
            </ConsolePage.Description>
          </ConsolePage.Heading>
          <ConsolePage.Actions>
            Runtime surface · revocation is auditable
          </ConsolePage.Actions>
        </ConsolePage.Header>

        <ConsolePage.Body data-page-slot="auth-sessions-page__body">
          <div
            {...stylex.props(pageStyles.pageFilters, styles.filters)}
            data-page-slot="auth-sessions-page__filters"
          >
            <DirectoryFilter ariaLabel="Session view" value="all">
              <option value="all">All sessions</option>
            </DirectoryFilter>
            <DirectoryFilter
              ariaLabel="Session expiry"
              onChange={(value) =>
                setExpiryFilter(value as AuthSessionExpiryFilter)
              }
              value={expiryFilter}
            >
              <option value="all">Any expiry</option>
              <option value="unexpired">Not expired</option>
              <option value="expired">Expired</option>
            </DirectoryFilter>
            <DirectoryFilter
              ariaLabel="Session state"
              onChange={(value) =>
                setStateFilter(value as AuthSessionStateFilter)
              }
              value={stateFilter}
            >
              <option value="all">Any state</option>
              <option value="active">Active</option>
              <option value="expired">Expired</option>
              <option value="revoked">Revoked</option>
            </DirectoryFilter>
          </div>

          {sessionsQuery.isPending ? (
            <DirectoryState
              description="Reading sessions from the selected Managed Service."
              title="Loading Auth sessions"
            />
          ) : sessionsQuery.isError ? (
            <DirectoryState
              description={errorMessage(sessionsQuery.error)}
              title="Auth sessions could not be loaded"
            />
          ) : (
            <SplitView
              data-page-slot="auth-sessions-page__workspace"
              inspectorWidth={376}
            >
              <SplitView.Main>
                <PaneHeader meta="Latest records" title="Session registry" />
                <DataGrid>
                  <TableHeader
                    columns={["Session", "Device", "Expires", "State"]}
                  />
                  {filteredRows.length === 0 ? (
                    <DirectoryState
                      description="Adjust the state filter to see other sessions."
                      title="No sessions match this filter"
                    />
                  ) : (
                    filteredRows.map((session) => (
                      <DataRow
                        cells={[
                          session.deviceId === "-"
                            ? "No device"
                            : session.deviceId,
                          formatAuthTimestamp(session.expiresAt),
                          <InlineStatus
                            key={`${session.id}-state`}
                            tone={statusTone(session.status)}
                          >
                            {titleCase(session.status)}
                          </InlineStatus>,
                        ]}
                        interactive
                        key={session.id}
                        onActivate={() => setSelectedSessionId(session.id)}
                        primary={session.id}
                        secondary={session.userId}
                        selected={selectedSession?.id === session.id}
                      />
                    ))
                  )}
                </DataGrid>
              </SplitView.Main>
              <SplitView.Inspector>
                <SessionInspector
                  canRevoke={canRevoke}
                  onRevoke={() => revokeSession.mutate(undefined)}
                  revokeSession={revokeSession}
                  session={selectedSession}
                />
              </SplitView.Inspector>
            </SplitView>
          )}
        </ConsolePage.Body>
      </ConsolePage>
    </SurfaceRoot>
  );
}

function UserInspector({
  actionRegistry,
  canManage,
  extensionActions,
  inspectorTab,
  mutation,
  onChangeTab,
  onDisable,
  onEnable,
  selectedAction,
  user,
}: {
  actionRegistry: readonly UserActionRegistryEntry[];
  canManage: boolean;
  extensionActions: readonly ConsoleResolvedOperationContribution[];
  inspectorTab: InspectorTab;
  mutation: AsyncMutationState<UserMutation>;
  onChangeTab: (tab: InspectorTab) => void;
  onDisable: (event: FormEvent<HTMLFormElement>) => void;
  onEnable: () => void;
  selectedAction: UserActionRegistryEntry | null;
  user: AuthUserRow | null;
}) {
  if (!user) {
    return (
      <DirectoryState
        description="Choose a user from the directory to inspect it."
        title="No user selected"
      />
    );
  }

  const isActionsView = inspectorTab === "actions";

  return (
    <Inspector
      status={
        <InlineStatus
          tone={
            isActionsView
              ? selectedAction?.available
                ? "success"
                : "neutral"
              : statusTone(user.status)
          }
        >
          {isActionsView
            ? selectedAction?.available
              ? "Available for selected user"
              : "Unavailable for selected user"
            : `${titleCase(user.status)} · created ${formatAuthDateLabel(user.createdAt)}`}
        </InlineStatus>
      }
      subtitle={
        isActionsView
          ? user.id
          : user.isAnonymous
            ? "Anonymous identity"
            : "Registered identity"
      }
      title={isActionsView ? "Actions" : user.id}
    >
      <Tabs density="inspector" stylex={styles.tabs}>
        <Tabs.List>
          {(["details", "sessions", "actions"] as const).map((tab) => (
            <Tabs.Tab
              key={tab}
              onClick={() => onChangeTab(tab)}
              selected={inspectorTab === tab}
            >
              {titleCase(tab)}
            </Tabs.Tab>
          ))}
        </Tabs.List>
        <Tabs.Panel>
          {inspectorTab === "details" ? (
            <>
              <Inspector.Section title="Identity">
                <InspectorLines
                  items={[
                    `Anonymous: ${user.isAnonymous ? "yes" : "no"}`,
                    "Device: -",
                    `Created: ${formatAuthTimestamp(user.createdAt)}`,
                  ]}
                />
              </Inspector.Section>
              <Inspector.Section title="Access state">
                <InspectorLines
                  items={[
                    `Disabled: ${user.status === "disabled" ? "yes" : "no"}`,
                    `Reason: ${user.disabledReason}`,
                    `Until: ${formatAuthTimestamp(user.disabledUntil)}`,
                  ]}
                />
              </Inspector.Section>
              <Inspector.Section title="Surface">
                <InspectorLines
                  items={[
                    "Workspace: Auth",
                    "Group: Directory",
                    "Surface: Users",
                  ]}
                />
              </Inspector.Section>
              <Inspector.Section title="Extension actions">
                <InspectorLines
                  items={
                    extensionActions.length > 0
                      ? [
                          ...extensionActions.map((action) => action.label),
                          `Slot: ${AUTH_USERS_DETAIL_ACTIONS_SLOT}`,
                        ]
                      : ["No installed Auth module contributes an operation."]
                  }
                />
              </Inspector.Section>
            </>
          ) : inspectorTab === "sessions" ? (
            <StateView
              action={
                <span {...stylex.props(styles.mono)}>
                  Open Sessions from the Auth workspace.
                </span>
              }
              description="Session records remain independently capability-gated."
              title="Related sessions"
            />
          ) : (
            <UserActions
              actions={actionRegistry}
              canManage={canManage}
              mutation={mutation}
              onDisable={onDisable}
              onEnable={onEnable}
              selectedAction={selectedAction}
              user={user}
            />
          )}
        </Tabs.Panel>
      </Tabs>
    </Inspector>
  );
}

function UserActions({
  actions,
  canManage,
  mutation,
  onDisable,
  onEnable,
  selectedAction,
  user,
}: {
  actions: readonly UserActionRegistryEntry[];
  canManage: boolean;
  mutation: AsyncMutationState<UserMutation>;
  onDisable: (event: FormEvent<HTMLFormElement>) => void;
  onEnable: () => void;
  selectedAction: UserActionRegistryEntry | null;
  user: AuthUserRow;
}) {
  const [coreControl, setCoreControl] = useState<"disable" | null>(null);
  const extensionActions = actions.filter(
    (action) => action.kind === "Extension"
  );

  useEffect(() => {
    setCoreControl(null);
  }, [selectedAction?.id]);

  if (!selectedAction) {
    return (
      <DirectoryState
        description="No core or module-contributed action is registered for this user."
        title="No action selected"
      />
    );
  }

  return (
    <div {...stylex.props(styles.actionStack)}>
      <Inspector.Section title="Core controls">
        <InspectorLines
          items={["Disable user", "Enable user", "Capability-gated"]}
        />
      </Inspector.Section>

      {extensionActions.map((action) => (
        <Inspector.Section
          key={action.id}
          title={`${extensionLabel(action.owner)} extension`}
        >
          <InspectorLines
            items={[
              action.label,
              `Owner: ${action.owner}`,
              "Slot contribution",
            ]}
          />
        </Inspector.Section>
      ))}

      {coreControl === "disable" && user.status === "active" ? (
        <Inspector.Section title="Confirm disable user">
          <form {...stylex.props(styles.actionForm)} onSubmit={onDisable}>
            <Field>
              <Field.Label>Reason</Field.Label>
              <Input name="reason" placeholder="Optional operator reason" />
            </Field>
            <Field>
              <Field.Label>Disable until</Field.Label>
              <Input name="disabled_until" type="datetime-local" />
            </Field>
            <Button
              disabled={!canManage || mutation.isPending}
              type="submit"
              variant="danger"
            >
              {mutation.isPending ? "Disabling…" : "Disable user"}
            </Button>
          </form>
        </Inspector.Section>
      ) : null}

      <Inspector.Section title="Execution">
        <InspectorLines
          items={[
            "Confirmation required",
            "Receipts retained",
            "Effects owned by modules",
          ]}
        />
        {mutation.isError ? (
          <p {...stylex.props(styles.feedback)}>
            {errorMessage(mutation.error)}
          </p>
        ) : null}
        {!canManage && selectedAction.kind === "Core"
          ? "This operator cannot manage Auth users."
          : null}
      </Inspector.Section>

      <Inspector.Actions>
        {user.status === "active" ? (
          <Button
            disabled={!canManage || mutation.isPending}
            onClick={() => setCoreControl("disable")}
            variant="danger"
          >
            Disable user
          </Button>
        ) : (
          <Button
            disabled={!canManage || mutation.isPending}
            onClick={onEnable}
            variant="primary"
          >
            {mutation.isPending ? "Enabling…" : "Enable user"}
          </Button>
        )}
        {extensionActions.map((action) => (
          <Button
            disabled
            key={action.id}
            title="This contribution is registered, but generic contribution execution is not exposed by the current Console Surface API."
          >
            {action.label}
          </Button>
        ))}
      </Inspector.Actions>
    </div>
  );
}

function SessionInspector({
  canRevoke,
  onRevoke,
  revokeSession,
  session,
}: {
  canRevoke: boolean;
  onRevoke: () => void;
  revokeSession: AsyncMutationState<undefined>;
  session: AuthSessionRow | null;
}) {
  const [tab, setTab] = useState<SessionInspectorTab>("details");

  if (!session) {
    return (
      <DirectoryState
        description="Choose a session from the directory to inspect it."
        title="No session selected"
      />
    );
  }

  return (
    <Inspector
      status={
        <InlineStatus tone={statusTone(session.status)}>
          {`${titleCase(session.status)} · expires ${formatAuthDateLabel(session.expiresAt)}`}
        </InlineStatus>
      }
      subtitle={session.userId}
      title={session.id}
    >
      <Tabs density="inspector" stylex={styles.tabs}>
        <Tabs.List>
          <Tabs.Tab onClick={() => setTab("details")} selected={tab === "details"}>
            Details
          </Tabs.Tab>
          <Tabs.Tab onClick={() => setTab("evidence")} selected={tab === "evidence"}>
            Evidence
          </Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel>
          {tab === "details" ? (
            <>
              <Inspector.Section title="Session">
                <InspectorLines
                  items={[
                    `User: ${session.userId}`,
                    `Device: ${session.deviceId}`,
                    `Created: ${formatAuthTimestamp(session.createdAt)}`,
                  ]}
                />
              </Inspector.Section>
              <Inspector.Section title="Client">
                <InspectorLines
                  items={[
                    `IP: ${session.clientIp}`,
                    `Agent: ${session.userAgent}`,
                    session.deviceId === "-" ? "No device" : "Device bound",
                  ]}
                />
              </Inspector.Section>
              <Inspector.Section title="Lifecycle">
                <InspectorLines
                  items={[
                    `Expires: ${formatAuthTimestamp(session.expiresAt)}`,
                    `Revoked: ${formatAuthTimestamp(session.revokedAt)}`,
                    `State: ${session.status}`,
                  ]}
                />
              </Inspector.Section>
              <Inspector.Section title="Evidence">
                <InspectorLines
                  items={[
                    "Action: revoke_session",
                    "Owner: auth",
                    "Receipt retained",
                  ]}
                />
              </Inspector.Section>
            </>
          ) : (
            <Inspector.Section title="Revocation evidence">
              <KeyValueList>
                <KeyValueList.Row label="Action" value="revoke_session" />
                <KeyValueList.Row label="Owner" value="auth" />
                <KeyValueList.Row
                  label="Revoked"
                  value={formatAuthTimestamp(session.revokedAt)}
                />
                <KeyValueList.Row label="Receipt" value="Retained" />
              </KeyValueList>
            </Inspector.Section>
          )}
        </Tabs.Panel>
      </Tabs>
      {session.status === "active" ? (
        <Inspector.Actions>
          <Button
            disabled={!canRevoke || revokeSession.isPending}
            onClick={onRevoke}
            variant="danger"
          >
            {revokeSession.isPending ? "Revoking…" : "Revoke session"}
          </Button>
          {!canRevoke ? "This operator cannot revoke Auth sessions." : null}
          {revokeSession.isError ? (
            <p {...stylex.props(styles.feedback)}>
              {errorMessage(revokeSession.error)}
            </p>
          ) : null}
        </Inspector.Actions>
      ) : null}
    </Inspector>
  );
}

function DirectoryFilter({
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

function InspectorLines({ items }: { items: readonly ReactNode[] }) {
  return (
    <div {...stylex.props(styles.inspectorLines)}>
      {items.map((item, index) => (
        <span key={index}>{item}</span>
      ))}
    </div>
  );
}

function DirectoryState({
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

interface AsyncQueryState<T> {
  readonly data?: T;
  readonly error: unknown;
  readonly isError: boolean;
  readonly isPending: boolean;
  readonly refetch: () => void;
}

function useAsyncQuery<T>(load: () => Promise<T>): AsyncQueryState<T> {
  const [revision, setRevision] = useState(0);
  const [state, setState] = useState<Omit<AsyncQueryState<T>, "refetch">>({
    error: null,
    isError: false,
    isPending: true,
  });

  useEffect(() => {
    let active = true;
    setState((current) => ({ ...current, error: null, isError: false, isPending: true }));
    void load()
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
  }, [load, revision]);

  const refetch = useCallback(() => setRevision((value) => value + 1), []);
  return { ...state, refetch };
}

interface AsyncMutationState<Input> {
  readonly error: unknown;
  readonly isError: boolean;
  readonly isPending: boolean;
  readonly mutate: (input: Input) => void;
}

function useAsyncMutation<Input>(
  execute: (input: Input) => Promise<unknown>,
  onSuccess: () => void
): AsyncMutationState<Input> {
  const [state, setState] = useState<
    Omit<AsyncMutationState<Input>, "mutate">
  >({ error: null, isError: false, isPending: false });
  const mutate = useCallback(
    (input: Input) => {
      setState({ error: null, isError: false, isPending: true });
      void execute(input)
        .then(() => {
          setState({ error: null, isError: false, isPending: false });
          onSuccess();
        })
        .catch((error: unknown) => {
          setState({ error, isError: true, isPending: false });
        });
    },
    [execute, onSuccess]
  );
  return { ...state, mutate };
}

function userActionRegistry(
  user: AuthUserRow | null,
  canManage: boolean,
  contributions: readonly ConsoleResolvedOperationContribution[],
  capabilities: { readonly has: (capability: string) => boolean }
): UserActionRegistryEntry[] {
  const coreActions: UserActionRegistryEntry[] = [
    {
      available: Boolean(user && user.status === "active" && canManage),
      effect: "Blocks new sessions",
      id: "auth:disable-user",
      kind: "Core",
      label: "Disable user",
      operationId: "auth/disable-user",
      owner: "auth",
    },
    {
      available: Boolean(user && user.status === "disabled" && canManage),
      effect: "Restores access",
      id: "auth:enable-user",
      kind: "Core",
      label: "Enable user",
      operationId: "auth/enable-user",
      owner: "auth",
    },
  ];
  const extensionActions = contributions.map((contribution) => ({
    available: Boolean(
      user &&
        contribution.requiredCapabilities.every((capability) =>
          capabilities.has(capability)
        )
    ),
    effect: contribution.label.toLowerCase().includes("password")
      ? "Rotates credential"
      : "Module-contributed effect",
    id: contribution.key,
    kind: "Extension" as const,
    label: contribution.label,
    operationId: contribution.operationId,
    owner: contribution.key.split(/[.:]/u)[0] || "auth-extension",
  }));

  return [...coreActions, ...extensionActions];
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function statusTone(
  status: AuthUserRow["status"] | AuthSessionRow["status"]
): SemanticTone {
  if (status === "active") {
    return "success";
  }
  return "danger";
}

function formatAuthDateLabel(value: string): string {
  if (value === "-") {
    return value;
  }
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    return value;
  }
  return new Intl.DateTimeFormat("en", {
    day: "numeric",
    month: "short",
    timeZone: "UTC",
  }).format(new Date(timestamp));
}

function extensionLabel(owner: string): string {
  return titleCase(owner.replace(/^auth-/u, ""));
}

function titleCase(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
