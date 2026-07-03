import { runtimeConsoleHostApi } from "@lenso/runtime-console-api";
import type { ReactNode } from "react";

import {
  providerDetail,
  providerSummaries,
  routeLabel,
  type ModuleHttpRouteLike,
  type ProviderKind,
  type ProviderModuleMetadataLike,
  type ProviderSummary,
} from "./model";

type ProviderConsoleHostApi = typeof runtimeConsoleHostApi & {
  modules: {
    useMetadata: () => {
      data?: { modules: ProviderModuleMetadataLike[] };
      error: unknown;
      isError: boolean;
      isPending: boolean;
    };
  };
};

const consoleHostApi = runtimeConsoleHostApi as ProviderConsoleHostApi;

export const AuthProvidersPage = () => {
  const modulesQuery = consoleHostApi.modules.useMetadata();
  const summaries = providerSummaries(modulesQuery.data?.modules ?? []);

  return (
    <ProviderShell
      error={modulesQuery.error}
      isError={modulesQuery.isError}
      isPending={modulesQuery.isPending}
      subtitle={`${summaries.filter((provider) => provider.status === "loaded").length} loaded`}
      title="Providers"
    >
      <div className="grid min-h-0 grid-rows-[auto_minmax(0,1fr)] overflow-hidden">
        <div className="grid border-b border-(--border-subtle) bg-(--surface) md:grid-cols-3">
          {[
            ["loaded", summaries.filter((item) => item.status === "loaded").length],
            ["missing", summaries.filter((item) => item.status === "missing").length],
            ["routes", summaries.reduce((sum, item) => sum + item.routeCount, 0)],
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
        <div className="min-h-0 overflow-auto">
          {summaries.map((provider) => (
            <ProviderSummaryRow key={provider.kind} provider={provider} />
          ))}
        </div>
      </div>
    </ProviderShell>
  );
};

export const GitHubProviderPage = () => (
  <ProviderDetailPage kind="github" title="GitHub" />
);

export const GoogleProviderPage = () => (
  <ProviderDetailPage kind="google" title="Google" />
);

export const OidcProviderPage = () => (
  <ProviderDetailPage kind="oidc" title="OIDC Provider" />
);

function ProviderDetailPage({
  kind,
  title,
}: {
  kind: ProviderKind;
  title: string;
}) {
  const modulesQuery = consoleHostApi.modules.useMetadata();
  const detail = providerDetail(modulesQuery.data?.modules ?? [], kind);

  return (
    <ProviderShell
      error={modulesQuery.error}
      isError={modulesQuery.isError}
      isPending={modulesQuery.isPending}
      subtitle={detail.summary?.status ?? "missing"}
      title={title}
    >
      {detail.summary ? (
        <div className="grid min-h-0 grid-cols-[minmax(0,1fr)_clamp(280px,28vw,380px)] overflow-hidden">
          <section className="grid min-h-0 grid-rows-[auto_minmax(0,1fr)] overflow-hidden border-r border-(--border-subtle)">
            <SectionHeader
              meta={`${detail.routes.length} routes`}
              title="Routes"
            />
            <ProviderRoutesTable routes={detail.routes} />
          </section>
          <aside className="min-h-0 overflow-auto bg-(--sidebar)">
            <SectionHeader meta={detail.summary.status} title="Module" />
            <Metric label="module" value={detail.summary.moduleName} />
            <Metric
              label="dependencies"
              value={detail.summary.dependencies.join(", ") || "-"}
            />
            <Metric label="error" value={detail.summary.error} />
          </aside>
        </div>
      ) : (
        <PanelMessage value="Provider module not found" />
      )}
    </ProviderShell>
  );
}

function ProviderShell({
  children,
  error,
  isError,
  isPending,
  subtitle,
  title,
}: {
  children: ReactNode;
  error: unknown;
  isError: boolean;
  isPending: boolean;
  subtitle: string;
  title: string;
}) {
  if (isError) {
    return (
      <main className="h-full bg-(--background) text-(--foreground)">
        <PanelMessage
          tone="error"
          value={String((error as Error | undefined)?.message)}
        />
      </main>
    );
  }
  if (isPending) {
    return (
      <main className="h-full bg-(--background) text-(--foreground)">
        <PanelMessage value="Loading provider metadata" />
      </main>
    );
  }
  return (
    <main className="grid h-full min-h-0 min-w-0 grid-rows-[auto_minmax(0,1fr)] overflow-hidden bg-(--background) text-(--foreground)">
      <header className="border-b border-(--border-subtle) bg-(--surface) px-3 py-2">
        <div className="flex min-w-0 items-center gap-2">
          <h1 className="font-mono text-[13px] font-semibold">{title}</h1>
          <span className="ml-auto font-mono text-[10px] text-(--muted)">
            {subtitle}
          </span>
        </div>
      </header>
      {children}
    </main>
  );
}

function ProviderSummaryRow({ provider }: { provider: ProviderSummary }) {
  return (
    <div className="grid min-h-11 min-w-180 grid-cols-[minmax(180px,1fr)_120px_120px_minmax(180px,0.8fr)] items-center border-b border-(--border-subtle) px-3 py-2 font-mono text-[11px]">
      <span className="truncate text-(--foreground)">{provider.label}</span>
      <StatusPill status={provider.status} />
      <span className="truncate text-(--muted)">
        {provider.routeCount} routes
      </span>
      <span className="truncate text-(--muted)">
        {provider.dependencies.join(", ") || "-"}
      </span>
    </div>
  );
}

function ProviderRoutesTable({
  routes,
}: {
  routes: readonly ModuleHttpRouteLike[];
}) {
  if (routes.length === 0) {
    return <PanelMessage value="No provider routes found" />;
  }
  return (
    <div className="min-h-0 overflow-auto">
      <div className="grid min-w-210 grid-cols-[80px_minmax(220px,1fr)_minmax(180px,0.8fr)] border-b border-(--border-subtle) bg-(--surface) px-3 py-1.5 font-mono text-[10px] text-(--muted)">
        <span>Method</span>
        <span>Path</span>
        <span>Name</span>
      </div>
      {routes.map((route, index) => (
        <div
          className="grid min-h-10 min-w-210 grid-cols-[80px_minmax(220px,1fr)_minmax(180px,0.8fr)] items-center border-b border-(--border-subtle) px-3 py-2 font-mono text-[11px]"
          key={`${route.method ?? "GET"}:${route.path ?? index}`}
        >
          <span className="truncate text-(--foreground)">
            {route.method ?? "-"}
          </span>
          <span className="truncate text-(--muted)">{route.path ?? "-"}</span>
          <span className="truncate text-(--muted)">{routeLabel(route)}</span>
        </div>
      ))}
    </div>
  );
}

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

function StatusPill({ status }: { status: ProviderSummary["status"] }) {
  const tone =
    status === "loaded"
      ? "bg-[var(--tone-success-bg)] text-(--tone-success-fg) border-[var(--tone-success-border)]"
      : status === "error"
        ? "bg-[var(--tone-error-bg)] text-(--tone-error-fg) border-[var(--tone-error-border)]"
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
