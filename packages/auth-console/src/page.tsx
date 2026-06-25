import { runtimeConsoleHostApi } from "@lenso/runtime-console-api";
import { useState, type FormEvent } from "react";

import {
  CONSOLE_ADMIN_USER_SCOPES_CONFIG_KEY,
  CONSOLE_ADMIN_USER_SCOPES_SERVICE,
  authSessionRows,
  authSessionsSummary,
  authUserRows,
  authUsersSummary,
  consoleAdminAccessForUser,
  consoleAdminUserScopes,
  setConsoleAdminUserAccess,
  type AuthSessionRow,
  type AuthUserRow,
  type ConsoleAdminAccess,
  type ConsoleConfigValueLike,
} from "./model";

type ConsoleConfigHostApi = typeof runtimeConsoleHostApi & {
  config: {
    useValues: () => {
      data?: { data: ConsoleConfigValueLike[] };
      error: unknown;
      isError: boolean;
      isPending: boolean;
    };
    useWriteValue: () => {
      error: unknown;
      isError: boolean;
      isPending: boolean;
      mutate: (request: {
        key: string;
        service: string;
        value: unknown;
      }) => void;
    };
  };
};

const consoleHostApi = runtimeConsoleHostApi as ConsoleConfigHostApi;

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
    return (
      <PanelMessage
        tone="error"
        value={String((error as Error | undefined)?.message)}
      />
    );
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
    return (
      <PanelMessage
        tone="error"
        value={String((error as Error | undefined)?.message)}
      />
    );
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
            <span className="truncate text-(--muted)">{session.createdAt}</span>
            <span className="truncate text-(--muted)">{session.expiresAt}</span>
            <StatusPill status={session.status} />
          </button>
        );
      })}
    </div>
  );
};

const AuthUsersSurfacePage = () => {
  const usersQuery = runtimeConsoleHostApi.adminData.useRecords({
    entityName: "users",
    moduleName: "auth",
  });
  const userAction = runtimeConsoleHostApi.adminData.useInvokeAction();
  const configValuesQuery = consoleHostApi.config.useValues();
  const writeConfigValue = consoleHostApi.config.useWriteValue();
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const userRows = authUserRows(usersQuery.data?.data ?? []);
  const summary = authUsersSummary(usersQuery.data?.data ?? []);
  const configValues = configValuesQuery.data?.data ?? [];
  const selectedUser =
    userRows.find((user) => user.id === selectedUserId) ?? userRows[0] ?? null;
  const selectedConsoleAccess = selectedUser
    ? consoleAdminAccessForUser(selectedUser.id, configValues)
    : null;
  const updateConsoleAccess = (enabled: boolean) => {
    if (!selectedUser) {
      return;
    }
    writeConfigValue.mutate({
      key: CONSOLE_ADMIN_USER_SCOPES_CONFIG_KEY,
      service: CONSOLE_ADMIN_USER_SCOPES_SERVICE,
      value: setConsoleAdminUserAccess(
        consoleAdminUserScopes(configValues),
        selectedUser.id,
        enabled
      ),
    });
  };
  const disableUser = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedUser) {
      return;
    }
    const form = new FormData(event.currentTarget);
    const reason = String(form.get("reason") ?? "").trim();
    const until = String(form.get("disabled_until") ?? "").trim();
    const input: Record<string, string> = { user_id: selectedUser.id };
    if (reason.length > 0) {
      input.reason = reason;
    }
    if (until.length > 0) {
      input.disabled_until = new Date(until).toISOString();
    }
    userAction.mutate({
      actionName: "disable_user",
      input,
      moduleName: "auth",
    });
  };

  return (
    <main className="grid h-full min-h-0 min-w-0 grid-rows-[auto_auto_minmax(0,1fr)] overflow-hidden bg-(--background) text-(--foreground)">
      <header className="border-b border-(--border-subtle) bg-(--surface) px-3 py-2">
        <div className="flex min-w-0 items-center gap-2">
          <h1 className="font-mono text-[13px] font-semibold">Users</h1>
          <span className="ml-auto font-mono text-[10px] text-(--muted)">
            {userRows.length} records
          </span>
        </div>
      </header>

      <div className="grid border-b border-(--border-subtle) bg-(--surface) md:grid-cols-3">
        {[
          ["total", summary.total],
          ["active", summary.active],
          ["disabled", summary.disabled],
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
              <ConsoleAccessPanel
                access={selectedConsoleAccess}
                error={configValuesQuery.error}
                isError={configValuesQuery.isError}
                isPending={configValuesQuery.isPending}
                isWriting={writeConfigValue.isPending}
                onToggle={updateConsoleAccess}
                writeError={writeConfigValue.error}
                writeIsError={writeConfigValue.isError}
              />
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
                        name="reason"
                        type="text"
                      />
                    </label>
                    <label className="grid gap-1 font-mono text-[10px] text-(--muted)">
                      Until
                      <input
                        aria-label="Disable until"
                        className="h-7 border border-(--border-subtle) bg-(--bg-control) px-2 text-[11px] text-(--foreground)"
                        name="disabled_until"
                        type="datetime-local"
                      />
                    </label>
                    <button
                      className="h-7 justify-self-start border border-[var(--tone-error-border)] bg-[var(--tone-error-bg)] px-2 font-mono text-[11px] font-semibold text-(--tone-error-fg) disabled:opacity-45"
                      disabled={userAction.isPending}
                      type="submit"
                    >
                      {userAction.isPending ? "Disabling" : "Disable"}
                    </button>
                  </form>
                ) : (
                  <button
                    className="h-7 border border-[var(--tone-success-border)] bg-[var(--tone-success-bg)] px-2 font-mono text-[11px] font-semibold text-(--tone-success-fg) disabled:opacity-45"
                    disabled={userAction.isPending}
                    onClick={() =>
                      userAction.mutate({
                        actionName: "enable_user",
                        input: { user_id: selectedUser.id },
                        moduleName: "auth",
                      })
                    }
                    type="button"
                  >
                    {userAction.isPending ? "Enabling" : "Enable"}
                  </button>
                )}
                {userAction.isError ? (
                  <div className="mt-1 truncate font-mono text-[10px] text-(--error)">
                    {String((userAction.error as Error).message)}
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
  );
};

const AuthSessionsSurfacePage = () => {
  const sessionsQuery = runtimeConsoleHostApi.adminData.useRecords({
    entityName: "sessions",
    moduleName: "auth",
  });
  const revokeSession = runtimeConsoleHostApi.adminData.useInvokeAction();
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(
    null
  );
  const sessionRows = authSessionRows(sessionsQuery.data?.data ?? []);
  const summary = authSessionsSummary(sessionsQuery.data?.data ?? []);
  const selectedSession =
    sessionRows.find((session) => session.id === selectedSessionId) ??
    sessionRows[0] ??
    null;

  return (
    <main className="grid h-full min-h-0 min-w-0 grid-rows-[auto_auto_minmax(0,1fr)] overflow-hidden bg-(--background) text-(--foreground)">
      <header className="border-b border-(--border-subtle) bg-(--surface) px-3 py-2">
        <div className="flex min-w-0 items-center gap-2">
          <h1 className="font-mono text-[13px] font-semibold">Sessions</h1>
          <span className="ml-auto font-mono text-[10px] text-(--muted)">
            {sessionRows.length} records
          </span>
        </div>
      </header>

      <div className="grid border-b border-(--border-subtle) bg-(--surface) md:grid-cols-4">
        {[
          ["total", summary.total],
          ["active", summary.active],
          ["expired", summary.expired],
          ["revoked", summary.revoked],
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
                    disabled={revokeSession.isPending}
                    onClick={() =>
                      revokeSession.mutate({
                        actionName: "revoke_session",
                        input: { session_id: selectedSession.id },
                        moduleName: "auth",
                      })
                    }
                    type="button"
                  >
                    {revokeSession.isPending ? "Revoking" : "Revoke"}
                  </button>
                  {revokeSession.isError ? (
                    <div className="mt-1 truncate font-mono text-[10px] text-(--error)">
                      {String((revokeSession.error as Error).message)}
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
  );
};

export const AuthSessionsPage = AuthSessionsSurfacePage;

export const AuthUsersPage = AuthUsersSurfacePage;

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

function ConsoleAccessPanel({
  access,
  error,
  isError,
  isPending,
  isWriting,
  onToggle,
  writeError,
  writeIsError,
}: {
  access: ConsoleAdminAccess | null;
  error: unknown;
  isError: boolean;
  isPending: boolean;
  isWriting: boolean;
  onToggle: (enabled: boolean) => void;
  writeError: unknown;
  writeIsError: boolean;
}) {
  const enabled = access?.enabled ?? false;
  const status = access
    ? `${enabled ? "enabled" : "disabled"}${
        access.pendingRestart ? ", pending restart" : ""
      }`
    : "-";
  const scopes =
    access && access.scopes.length > 0 ? access.scopes.join(", ") : "-";
  let actionLabel = enabled ? "Revoke console access" : "Grant console access";
  if (isWriting) {
    actionLabel = "Saving";
  }

  return (
    <div className="border-b border-(--border-subtle) bg-(--surface) px-3 py-2 font-mono">
      <div className="text-[10px] text-(--muted)">console access</div>
      <div className="mt-1 truncate text-[12px] font-semibold text-(--foreground)">
        {isPending ? "loading" : status}
      </div>
      <div className="mt-1 truncate text-[10px] text-(--muted)">
        {isPending ? "-" : scopes}
      </div>
      <button
        className={[
          "mt-2 h-7 border px-2 text-[11px] font-semibold disabled:opacity-45",
          enabled
            ? "border-[var(--tone-error-border)] bg-[var(--tone-error-bg)] text-(--tone-error-fg)"
            : "border-[var(--tone-success-border)] bg-[var(--tone-success-bg)] text-(--tone-success-fg)",
        ].join(" ")}
        disabled={isPending || isWriting || isError}
        onClick={() => onToggle(!enabled)}
        type="button"
      >
        {actionLabel}
      </button>
      {isError ? (
        <div className="mt-1 truncate text-[10px] text-(--error)">
          {String((error as Error | undefined)?.message)}
        </div>
      ) : null}
      {writeIsError ? (
        <div className="mt-1 truncate text-[10px] text-(--error)">
          {String((writeError as Error | undefined)?.message)}
        </div>
      ) : null}
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
