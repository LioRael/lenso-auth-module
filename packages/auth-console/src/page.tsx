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
  type AuthPage,
  type AuthSessionRecord,
  type AuthUserRecord,
} from "./business-api";
import {
  authSessionRows,
  authSessionsSummary,
  authUserRows,
  authUsersSummary,
  filterAuthSessionRows,
  filterAuthUserRows,
  formatAuthTimestamp,
  type AuthIdentityFilter,
  type AuthSessionRow,
  type AuthSessionStateFilter,
  type AuthUserRow,
  type AuthUserStateFilter,
} from "./model";

const AUTH_USERS_DETAIL_ACTIONS_SLOT = "auth.users.detail.actions";
const AUTH_USERS_MANAGE = "auth.users.manage";
const AUTH_SESSIONS_REVOKE = "auth.sessions.revoke";

type InspectorTab = "actions" | "details" | "sessions";
type UserMutation =
  | { readonly kind: "disable"; readonly reason?: string; readonly until?: string }
  | { readonly kind: "enable" };

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
  const [inspectorTab, setInspectorTab] = useState<InspectorTab>("details");
  const records = usersQuery.data?.records;
  const rows = useMemo(() => authUserRows(records ?? []), [records]);
  const filteredRows = useMemo(
    () => filterAuthUserRows(rows, identityFilter, stateFilter),
    [identityFilter, rows, stateFilter]
  );
  const summary = useMemo(() => authUsersSummary(records ?? []), [records]);
  const selectedUser =
    filteredRows.find((user) => user.id === selectedUserId) ??
    filteredRows[0] ??
    rows.find((user) => user.id === selectedUserId) ??
    null;
  const detailActions = consoleHostApi.contributions.useSlot(
    AUTH_USERS_DETAIL_ACTIONS_SLOT,
    { selected_user: selectedUser ?? {} }
  );
  const extensionAction =
    detailActions.find((action) => action.kind === "operation") ?? null;
  const canManage = client.capabilities.has(AUTH_USERS_MANAGE);
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
            <ConsolePage.Title>Users</ConsolePage.Title>
            <ConsolePage.Description>
              User identities registered by Auth, with contract-bound access
              controls and extension actions.
            </ConsolePage.Description>
          </ConsolePage.Heading>
          <ConsolePage.Actions>
            Auth Business API · live runtime data
          </ConsolePage.Actions>
        </ConsolePage.Header>

        <ConsolePage.Body data-page-slot="auth-users-page__body">
          <div
            {...stylex.props(pageStyles.pageFilters, styles.filters)}
            data-page-slot="auth-users-page__filters"
          >
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
              onChange={(value) => setStateFilter(value as AuthUserStateFilter)}
              value={stateFilter}
            >
              <option value="all">Any state</option>
              <option value="active">Active</option>
              <option value="disabled">Disabled</option>
            </DirectoryFilter>
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
                  meta={`${filteredRows.length} of ${summary.total}`}
                  title="Directory"
                />
                <DataGrid>
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
                </DataGrid>
              </SplitView.Main>
              <SplitView.Inspector>
                <UserInspector
                  canManage={canManage}
                  extensionAction={extensionAction}
                  inspectorTab={inspectorTab}
                  mutation={userMutation}
                  onChangeTab={setInspectorTab}
                  onDisable={disableUser}
                  onEnable={() => userMutation.mutate({ kind: "enable" })}
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
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(
    null
  );
  const records = sessionsQuery.data?.records;
  const rows = useMemo(() => authSessionRows(records ?? []), [records]);
  const filteredRows = useMemo(
    () => filterAuthSessionRows(rows, stateFilter),
    [rows, stateFilter]
  );
  const summary = useMemo(() => authSessionsSummary(records ?? []), [records]);
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
              Active and historical authentication sessions for the selected
              Managed Service.
            </ConsolePage.Description>
          </ConsolePage.Heading>
          <ConsolePage.Actions>
            {summary.active} active · {summary.expired} expired · {summary.revoked}{" "}
            revoked
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
                <PaneHeader
                  meta={`${filteredRows.length} of ${summary.total}`}
                  title="Session directory"
                />
                <DataGrid>
                  <TableHeader
                    columns={["Session", "User", "Created", "State"]}
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
                          session.userId,
                          formatAuthTimestamp(session.createdAt),
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
                        secondary={
                          session.deviceId === "-"
                            ? "Unbound device"
                            : session.deviceId
                        }
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
  canManage,
  extensionAction,
  inspectorTab,
  mutation,
  onChangeTab,
  onDisable,
  onEnable,
  user,
}: {
  canManage: boolean;
  extensionAction: ConsoleResolvedOperationContribution | null;
  inspectorTab: InspectorTab;
  mutation: AsyncMutationState<UserMutation>;
  onChangeTab: (tab: InspectorTab) => void;
  onDisable: (event: FormEvent<HTMLFormElement>) => void;
  onEnable: () => void;
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

  return (
    <Inspector
      status={
        <InlineStatus tone={statusTone(user.status)}>
          {titleCase(user.status)}
        </InlineStatus>
      }
      subtitle={user.isAnonymous ? "Anonymous identity" : "Registered identity"}
      title={user.id}
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
                <KeyValueList>
                  <KeyValueList.Row
                    label="Anonymous"
                    value={user.isAnonymous ? "Yes" : "No"}
                  />
                  <KeyValueList.Row
                    label="Created"
                    value={formatAuthTimestamp(user.createdAt)}
                  />
                </KeyValueList>
              </Inspector.Section>
              <Inspector.Section title="Access state">
                <KeyValueList>
                  <KeyValueList.Row
                    label="State"
                    value={titleCase(user.status)}
                  />
                  <KeyValueList.Row
                    label="Disabled"
                    value={formatAuthTimestamp(user.disabledAt)}
                  />
                  <KeyValueList.Row
                    label="Until"
                    value={formatAuthTimestamp(user.disabledUntil)}
                  />
                  <KeyValueList.Row label="Reason" value={user.disabledReason} />
                </KeyValueList>
              </Inspector.Section>
              <Inspector.Section title="Surface">
                <KeyValueList>
                  <KeyValueList.Row label="Source" value="Auth Business API" />
                  <KeyValueList.Row label="Mode" value="Live runtime data" />
                </KeyValueList>
              </Inspector.Section>
              <Inspector.Section title="Extension actions">
                {extensionAction
                  ? extensionAction.label
                  : "No installed Auth module contributes an operation."}
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
              canManage={canManage}
              extensionAction={extensionAction}
              mutation={mutation}
              onDisable={onDisable}
              onEnable={onEnable}
              user={user}
            />
          )}
        </Tabs.Panel>
      </Tabs>
    </Inspector>
  );
}

function UserActions({
  canManage,
  extensionAction,
  mutation,
  onDisable,
  onEnable,
  user,
}: {
  canManage: boolean;
  extensionAction: ConsoleResolvedOperationContribution | null;
  mutation: AsyncMutationState<UserMutation>;
  onDisable: (event: FormEvent<HTMLFormElement>) => void;
  onEnable: () => void;
  user: AuthUserRow;
}) {
  return (
    <div {...stylex.props(styles.actionStack)}>
      <Inspector.Section title="Access action">
        {user.status === "active" ? (
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
        ) : (
          <Button
            disabled={!canManage || mutation.isPending}
            onClick={onEnable}
            variant="primary"
          >
            {mutation.isPending ? "Enabling…" : "Enable user"}
          </Button>
        )}
        {!canManage ? "This operator cannot manage Auth users." : null}
        {mutation.isError ? (
          <p {...stylex.props(styles.feedback)}>
            {errorMessage(mutation.error)}
          </p>
        ) : null}
      </Inspector.Section>
      <Inspector.Section title="Extension action">
        {extensionAction ? (
          <KeyValueList>
            <KeyValueList.Row label="Action" value={extensionAction.label} />
            <KeyValueList.Row
              label="Operation"
              value={extensionAction.operationId}
            />
          </KeyValueList>
        ) : (
          "No installed Auth module contributes an operation."
        )}
      </Inspector.Section>
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
          {titleCase(session.status)}
        </InlineStatus>
      }
      subtitle={session.deviceId === "-" ? "Unbound device" : session.deviceId}
      title={session.id}
    >
      <Inspector.Section title="Identity">
        <KeyValueList>
          <KeyValueList.Row label="User" value={session.userId} />
          <KeyValueList.Row label="Device" value={session.deviceId} />
          <KeyValueList.Row label="Client IP" value={session.clientIp} />
          <KeyValueList.Row label="User agent" value={session.userAgent} />
        </KeyValueList>
      </Inspector.Section>
      <Inspector.Section title="Lifetime">
        <KeyValueList>
          <KeyValueList.Row
            label="Created"
            value={formatAuthTimestamp(session.createdAt)}
          />
          <KeyValueList.Row
            label="Expires"
            value={formatAuthTimestamp(session.expiresAt)}
          />
          <KeyValueList.Row
            label="Revoked"
            value={formatAuthTimestamp(session.revokedAt)}
          />
        </KeyValueList>
      </Inspector.Section>
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

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function statusTone(
  status: AuthUserRow["status"] | AuthSessionRow["status"]
): SemanticTone {
  if (status === "active") {
    return "success";
  }
  if (status === "expired") {
    return "neutral";
  }
  return "danger";
}

function titleCase(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1);
}
