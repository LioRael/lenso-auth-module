import {
  hasCapabilities,
  useConsoleAction,
  useConsoleRecords,
  useUserActionContributions,
  type ManagedActionContribution,
} from "@lenso/auth-console-shared";
import {
  ConsolePage,
  SurfaceRoot,
  useConsoleClient,
} from "@lenso/console-ui";
import { useState, type FormEvent } from "react";

import {
  authSessionRows,
  authSessionsSummary,
  authUserRows,
  authUsersSummary,
  type AuthSessionRow,
  type AuthUserRow,
} from "./model";

const AUTH_MODULE = "auth";
const AUTH_USERS_MANAGE = "auth.users.manage";
const AUTH_SESSIONS_REVOKE = "auth.sessions.revoke";

const AuthUsersTable = ({
  error,
  isError,
  isPending,
  onSelect,
  rows,
  selectedUser,
}: {
  error: unknown;
  isError: boolean;
  isPending: boolean;
  onSelect: (userId: string) => void;
  rows: ReturnType<typeof authUserRows>;
  selectedUser: AuthUserRow | null;
}) => {
  if (isError) {
    return <PanelMessage tone="error" value={errorMessage(error)} />;
  }
  if (isPending) {
    return <PanelMessage value="Loading auth users" />;
  }
  if (rows.length === 0) {
    return <PanelMessage value="No auth users found" />;
  }

  return (
    <div className="min-h-0 overflow-auto">
      <div className="grid min-w-240 grid-cols-[minmax(220px,1fr)_170px_170px_170px_88px] border-b border-(--border-subtle) bg-(--surface) px-3 py-1.5 font-mono text-[10px] text-(--muted)">
        <span>User</span>
        <span>Created</span>
        <span>Disabled</span>
        <span>Until</span>
        <span>Status</span>
      </div>
      {rows.map((user) => {
        const selected = selectedUser?.id === user.id;
        return (
          <button
            aria-pressed={selected}
            className={[
              "grid min-h-11 w-full min-w-240 grid-cols-[minmax(220px,1fr)_170px_170px_170px_88px] items-center gap-0 border-b border-(--border-subtle) px-3 py-2 text-left font-mono text-[11px] transition",
              selected ? "native-selection" : "hover:bg-(--bg-row-hover)",
            ].join(" ")}
            key={user.id}
            onClick={() => onSelect(user.id)}
            type="button"
          >
            <span className="truncate text-(--foreground)">{user.id}</span>
            <span className="truncate text-(--muted)">{user.createdAt}</span>
            <span className="truncate text-(--muted)">{user.disabledAt}</span>
            <span className="truncate text-(--muted)">
              {user.disabledUntil}
            </span>
            <StatusPill status={user.status} />
          </button>
        );
      })}
    </div>
  );
};

const AuthSessionsTable = ({
  error,
  isError,
  isPending,
  onSelect,
  rows,
  selectedSession,
}: {
  error: unknown;
  isError: boolean;
  isPending: boolean;
  onSelect: (sessionId: string) => void;
  rows: ReturnType<typeof authSessionRows>;
  selectedSession: AuthSessionRow | null;
}) => {
  if (isError) {
    return <PanelMessage tone="error" value={errorMessage(error)} />;
  }
  if (isPending) {
    return <PanelMessage value="Loading auth sessions" />;
  }
  if (rows.length === 0) {
    return <PanelMessage value="No auth sessions found" />;
  }

  return (
    <div className="min-h-0 overflow-auto">
      <div className="grid min-w-230 grid-cols-[minmax(220px,1fr)_minmax(180px,0.8fr)_170px_170px_92px] border-b border-(--border-subtle) bg-(--surface) px-3 py-1.5 font-mono text-[10px] text-(--muted)">
        <span>Session</span>
        <span>User</span>
        <span>Created</span>
        <span>Expires</span>
        <span>Status</span>
      </div>
      {rows.map((session) => {
        const selected = selectedSession?.id === session.id;
        return (
          <button
            aria-pressed={selected}
            className={[
              "grid min-h-11 w-full min-w-230 grid-cols-[minmax(220px,1fr)_minmax(180px,0.8fr)_170px_170px_92px] items-center gap-0 border-b border-(--border-subtle) px-3 py-2 text-left font-mono text-[11px] transition",
              selected ? "native-selection" : "hover:bg-(--bg-row-hover)",
            ].join(" ")}
            key={session.id}
            onClick={() => onSelect(session.id)}
            type="button"
          >
            <span className="truncate text-(--foreground)">{session.id}</span>
            <span className="truncate text-(--muted)">{session.userId}</span>
            <span className="truncate text-(--muted)">
              {session.createdAt}
            </span>
            <span className="truncate text-(--muted)">
              {session.expiresAt}
            </span>
            <StatusPill status={session.status} />
          </button>
        );
      })}
    </div>
  );
};

const AuthUsersSurfacePage = () => {
  const client = useConsoleClient();
  const usersQuery = useConsoleRecords("users");
  const userAction = useConsoleAction();
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const userRows = authUserRows(usersQuery.data?.data ?? []);
  const summary = authUsersSummary(usersQuery.data?.data ?? []);
  const selectedUser =
    userRows.find((user) => user.id === selectedUserId) ?? userRows[0] ?? null;
  const contributionsQuery = useUserActionContributions(
    selectedUser?.id ?? null
  );
  const resetContribution = contributionsQuery.data?.find(
    (contribution) =>
      contribution.action.name === "reset_password" ||
      contribution.action.name === "reset_phone_password"
  );
  const canManage = client.capabilities.has(AUTH_USERS_MANAGE);
  const canReset = resetContribution
    ? hasCapabilities(client, resetContribution.requiredCapabilities)
    : false;

  const disableUser = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedUser || !canManage) {
      return;
    }
    const form = new FormData(event.currentTarget);
    const reason = String(form.get("reason") ?? "").trim();
    const until = String(form.get("disabled_until") ?? "").trim();
    const input: Record<string, unknown> = { user_id: selectedUser.id };
    if (reason.length > 0) {
      input.reason = reason;
    }
    if (until.length > 0) {
      input.disabled_until = new Date(until).toISOString();
    }
    userAction.mutate({
      actionName: "disable_user",
      input,
      moduleName: AUTH_MODULE,
    });
  };

  const resetPassword = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedUser || !resetContribution || !canReset) {
      return;
    }
    const form = new FormData(event.currentTarget);
    const newPassword = String(form.get("new_password") ?? "").trim();
    if (newPassword.length === 0) {
      return;
    }
    userAction.mutate({
      actionName: resetContribution.action.name,
      input: contributionInput(resetContribution, selectedUser.id, newPassword),
      moduleName: resetContribution.action.module,
    });
    event.currentTarget.reset();
  };

  return (
    <SurfaceRoot moduleId={AUTH_MODULE} surfaceId="users">
      <ConsolePage scroll={false}>
        <main className="grid h-full min-h-0 min-w-0 grid-rows-[auto_auto_minmax(0,1fr)] overflow-hidden bg-(--background) text-(--foreground)">
          <header className="border-b border-(--border-subtle) bg-(--surface) px-3 py-2">
            <div className="flex min-w-0 items-center gap-2">
              <h1 className="font-mono text-[13px] font-semibold">Users</h1>
              <span className="ml-auto font-mono text-[10px] text-(--muted)">
                {userRows.length} records
              </span>
            </div>
          </header>

          <SummaryStrip
            values={[
              ["total", summary.total],
              ["active", summary.active],
              ["disabled", summary.disabled],
            ]}
          />

          <div className="grid min-h-0 min-w-0 grid-cols-[minmax(0,1fr)_clamp(280px,28vw,380px)] overflow-hidden">
            <section className="grid min-h-0 min-w-0 grid-rows-[auto_minmax(0,1fr)] overflow-hidden border-r border-(--border-subtle)">
              <SectionHeader meta={`${userRows.length} records`} title="Users" />
              <AuthUsersTable
                error={usersQuery.error}
                isError={usersQuery.isError}
                isPending={usersQuery.isPending}
                onSelect={setSelectedUserId}
                rows={userRows}
                selectedUser={selectedUser}
              />
            </section>

            <aside className="grid min-h-0 min-w-0 grid-rows-[auto_minmax(0,1fr)] overflow-hidden bg-(--sidebar)">
              <SectionHeader
                meta={selectedUser ? selectedUser.status : "no selection"}
                title={selectedUser?.id ?? "User"}
              />
              {selectedUser ? (
                <div className="min-h-0 overflow-auto">
                  <Metric label="created" value={selectedUser.createdAt} />
                  <Metric label="disabled" value={selectedUser.disabledAt} />
                  <Metric label="reason" value={selectedUser.disabledReason} />
                  <Metric label="until" value={selectedUser.disabledUntil} />
                  <Metric label="status" value={selectedUser.status} />
                  {resetContribution && canReset ? (
                    <UserActionContributionPanel
                      contribution={resetContribution}
                      error={userAction.error}
                      isError={userAction.isError}
                      isPending={userAction.isPending}
                      onSubmit={resetPassword}
                    />
                  ) : null}
                  <div className="border-b border-(--border-subtle) bg-(--surface) px-3 py-2">
                    {selectedUser.status === "active" ? (
                      <form
                        className="grid gap-2"
                        key={selectedUser.id}
                        onSubmit={disableUser}
                      >
                        <label className="grid gap-1 font-mono text-[10px] text-(--muted)">
                          Reason
                          <input
                            aria-label="Disable reason"
                            className="h-7 border border-(--border-subtle) bg-(--bg-control) px-2 text-[11px] text-(--foreground)"
                            disabled={!canManage}
                            name="reason"
                            type="text"
                          />
                        </label>
                        <label className="grid gap-1 font-mono text-[10px] text-(--muted)">
                          Until
                          <input
                            aria-label="Disable until"
                            className="h-7 border border-(--border-subtle) bg-(--bg-control) px-2 text-[11px] text-(--foreground)"
                            disabled={!canManage}
                            name="disabled_until"
                            type="datetime-local"
                          />
                        </label>
                        <button
                          className="h-7 justify-self-start border border-[var(--tone-error-border)] bg-[var(--tone-error-bg)] px-2 font-mono text-[11px] font-semibold text-(--tone-error-fg) disabled:opacity-45"
                          disabled={!canManage || userAction.isPending}
                          type="submit"
                        >
                          {userAction.isPending ? "Disabling" : "Disable"}
                        </button>
                      </form>
                    ) : (
                      <button
                        className="h-7 border border-[var(--tone-success-border)] bg-[var(--tone-success-bg)] px-2 font-mono text-[11px] font-semibold text-(--tone-success-fg) disabled:opacity-45"
                        disabled={!canManage || userAction.isPending}
                        onClick={() =>
                          userAction.mutate({
                            actionName: "enable_user",
                            input: { user_id: selectedUser.id },
                            moduleName: AUTH_MODULE,
                          })
                        }
                        type="button"
                      >
                        {userAction.isPending ? "Enabling" : "Enable"}
                      </button>
                    )}
                    {userAction.isError ? (
                      <div className="mt-1 truncate font-mono text-[10px] text-(--error)">
                        {errorMessage(userAction.error)}
                      </div>
                    ) : null}
                    {contributionsQuery.isError ? (
                      <div className="mt-1 truncate font-mono text-[10px] text-(--error)">
                        {errorMessage(contributionsQuery.error)}
                      </div>
                    ) : null}
                  </div>
                </div>
              ) : (
                <PanelMessage value="Select a user" />
              )}
            </aside>
          </div>
        </main>
      </ConsolePage>
    </SurfaceRoot>
  );
};

const AuthSessionsSurfacePage = () => {
  const client = useConsoleClient();
  const sessionsQuery = useConsoleRecords("sessions");
  const revokeSession = useConsoleAction();
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(
    null
  );
  const sessionRows = authSessionRows(sessionsQuery.data?.data ?? []);
  const summary = authSessionsSummary(sessionsQuery.data?.data ?? []);
  const selectedSession =
    sessionRows.find((session) => session.id === selectedSessionId) ??
    sessionRows[0] ??
    null;
  const canRevoke = client.capabilities.has(AUTH_SESSIONS_REVOKE);

  return (
    <SurfaceRoot moduleId={AUTH_MODULE} surfaceId="sessions">
      <ConsolePage scroll={false}>
        <main className="grid h-full min-h-0 min-w-0 grid-rows-[auto_auto_minmax(0,1fr)] overflow-hidden bg-(--background) text-(--foreground)">
          <header className="border-b border-(--border-subtle) bg-(--surface) px-3 py-2">
            <div className="flex min-w-0 items-center gap-2">
              <h1 className="font-mono text-[13px] font-semibold">Sessions</h1>
              <span className="ml-auto font-mono text-[10px] text-(--muted)">
                {sessionRows.length} records
              </span>
            </div>
          </header>

          <SummaryStrip
            values={[
              ["total", summary.total],
              ["active", summary.active],
              ["expired", summary.expired],
              ["revoked", summary.revoked],
            ]}
          />

          <div className="grid min-h-0 min-w-0 grid-cols-[minmax(0,1fr)_clamp(280px,28vw,380px)] overflow-hidden">
            <section className="grid min-h-0 min-w-0 grid-rows-[auto_minmax(0,1fr)] overflow-hidden border-r border-(--border-subtle)">
              <SectionHeader
                meta={`${sessionRows.length} records`}
                title="Sessions"
              />
              <AuthSessionsTable
                error={sessionsQuery.error}
                isError={sessionsQuery.isError}
                isPending={sessionsQuery.isPending}
                onSelect={setSelectedSessionId}
                rows={sessionRows}
                selectedSession={selectedSession}
              />
            </section>

            <aside className="grid min-h-0 min-w-0 grid-rows-[auto_minmax(0,1fr)] overflow-hidden bg-(--sidebar)">
              <SectionHeader
                meta={selectedSession ? selectedSession.status : "no selection"}
                title={selectedSession?.id ?? "Session"}
              />
              {selectedSession ? (
                <div className="min-h-0 overflow-auto">
                  <Metric label="user" value={selectedSession.userId} />
                  <Metric label="created" value={selectedSession.createdAt} />
                  <Metric label="expires" value={selectedSession.expiresAt} />
                  <Metric label="revoked" value={selectedSession.revokedAt} />
                  <Metric label="status" value={selectedSession.status} />
                  {selectedSession.status === "active" ? (
                    <div className="border-b border-(--border-subtle) bg-(--surface) px-3 py-2">
                      <button
                        className="h-7 border border-[var(--tone-error-border)] bg-[var(--tone-error-bg)] px-2 font-mono text-[11px] font-semibold text-(--tone-error-fg) disabled:opacity-45"
                        disabled={!canRevoke || revokeSession.isPending}
                        onClick={() =>
                          revokeSession.mutate({
                            actionName: "revoke_session",
                            input: { session_id: selectedSession.id },
                            moduleName: AUTH_MODULE,
                          })
                        }
                        type="button"
                      >
                        {revokeSession.isPending ? "Revoking" : "Revoke"}
                      </button>
                      {revokeSession.isError ? (
                        <div className="mt-1 truncate font-mono text-[10px] text-(--error)">
                          {errorMessage(revokeSession.error)}
                        </div>
                      ) : null}
                    </div>
                  ) : null}
                </div>
              ) : (
                <PanelMessage value="Select a session" />
              )}
            </aside>
          </div>
        </main>
      </ConsolePage>
    </SurfaceRoot>
  );
};

export const AuthSessionsPage = AuthSessionsSurfacePage;
export const AuthUsersPage = AuthUsersSurfacePage;

function contributionInput(
  contribution: ManagedActionContribution,
  userId: string,
  newPassword: string
): Record<string, unknown> {
  const input: Record<string, unknown> = { new_password: newPassword };
  for (const binding of contribution.action.inputBindings ?? []) {
    if (binding.value.path === "selected_user.id") {
      input[binding.input] = userId;
    }
  }
  return input;
}

function SummaryStrip({
  values,
}: {
  values: readonly (readonly [string, number])[];
}) {
  return (
    <div className="grid border-b border-(--border-subtle) bg-(--surface) md:grid-cols-4">
      {values.map(([label, value]) => (
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
  );
}

function SectionHeader({ meta, title }: { meta: string; title: string }) {
  return (
    <header className="border-b border-(--border-subtle) bg-(--surface) px-3 py-2">
      <h2 className="font-mono text-[12px] font-semibold text-(--foreground)">
        {title}
      </h2>
      <p className="mt-0.5 truncate font-mono text-[10px] text-(--muted)">
        {meta}
      </p>
    </header>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="border-b border-(--border-subtle) bg-(--surface) px-3 py-2 font-mono">
      <div className="text-[10px] text-(--muted)">{label}</div>
      <div className="mt-1 truncate text-[12px] font-semibold text-(--foreground)">
        {value}
      </div>
    </div>
  );
}

function UserActionContributionPanel({
  contribution,
  error,
  isError,
  isPending,
  onSubmit,
}: {
  contribution: ManagedActionContribution;
  error: unknown;
  isError: boolean;
  isPending: boolean;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <div className="border-b border-(--border-subtle) bg-(--surface) px-3 py-2">
      <form className="grid gap-2" onSubmit={onSubmit}>
        <label className="grid gap-1 font-mono text-[10px] text-(--muted)">
          New password
          <input
            aria-label="New password"
            className="h-7 border border-(--border-subtle) bg-(--bg-control) px-2 text-[11px] text-(--foreground)"
            name="new_password"
            type="password"
          />
        </label>
        <button
          className="h-7 justify-self-start border border-[var(--tone-warning-border)] bg-[var(--tone-warning-bg)] px-2 font-mono text-[11px] font-semibold text-(--tone-warning-fg) disabled:opacity-45"
          disabled={isPending}
          type="submit"
        >
          {isPending ? "Resetting" : contribution.label}
        </button>
        {isError ? (
          <div className="truncate font-mono text-[10px] text-(--error)">
            {errorMessage(error)}
          </div>
        ) : null}
      </form>
    </div>
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

function StatusPill({
  status,
}: {
  status: AuthUserRow["status"] | AuthSessionRow["status"];
}) {
  return (
    <span
      className={[
        "inline-flex h-5 items-center justify-center border px-1.5 font-mono text-[10px] font-semibold",
        statusClassName(status),
      ].join(" ")}
    >
      {status}
    </span>
  );
}

function statusClassName(
  status: AuthUserRow["status"] | AuthSessionRow["status"]
) {
  if (status === "active") {
    return "border-[var(--tone-success-border)] bg-[var(--tone-success-bg)] text-(--tone-success-fg)";
  }
  if (status === "expired") {
    return "border-(--border-subtle) bg-(--bg-control) text-(--muted)";
  }
  return "border-[var(--tone-error-border)] bg-[var(--tone-error-bg)] text-(--tone-error-fg)";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error ?? "Unknown error");
}
