import { useManagedServiceInventory } from "@lenso/auth-console-shared";
import {
  Button,
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
  TableHeader,
  Tabs,
  pageStyles,
  type SemanticTone,
} from "@lenso/console-ui";
import * as stylex from "@stylexjs/stylex";
import { useMemo, useState, type ReactNode } from "react";

import {
  providerDetail,
  providerRouteDescription,
  providerSummaries,
  type ModuleHttpRouteLike,
  type ProviderKind,
  type ProviderSummary,
} from "./model";

type ProviderInspectorTab = "configuration" | "operations" | "overview";

const styles = stylex.create({
  filterChevron: {
    display: "inline-block",
    fontSize: 10,
    lineHeight: 1,
    transform: "translateY(-1px)",
  },
  filters: { flexWrap: "wrap" },
  inspectorLines: { display: "grid", gap: 5 },
  state: { backgroundColor: "var(--lenso-token-canvas, #000000)" },
  tabs: { marginBlockStart: 2 },
});

export function AuthProvidersPage() {
  const modulesQuery = useManagedServiceInventory();
  const summaries = useMemo(
    () => providerSummaries(modulesQuery.data?.modules ?? []),
    [modulesQuery.data?.modules]
  );
  const [selectedKind, setSelectedKind] = useState<ProviderKind>("github");
  const selected =
    summaries.find((provider) => provider.kind === selectedKind) ??
    summaries[0] ??
    null;

  return (
    <ProviderPage
      description="Registered sign-in surfaces and their module-owned configuration."
      filters={
        <>
          <ProviderFilter ariaLabel="Provider view" value="all">
            <option value="all">All providers</option>
          </ProviderFilter>
          <ProviderFilter ariaLabel="Provider module" value="any">
            <option value="any">Any module</option>
          </ProviderFilter>
          <ProviderFilter ariaLabel="Provider state" value="registered">
            <option value="registered">Registered</option>
          </ProviderFilter>
        </>
      }
      meta="Surface group · Sign-in"
      title="Providers"
    >
      {modulesQuery.isPending ? (
        <ProviderState
          description="Reading provider modules from the selected Managed Service."
          title="Loading provider surfaces"
        />
      ) : modulesQuery.isError ? (
        <ProviderState
          description={errorMessage(modulesQuery.error)}
          title="Provider surfaces could not be loaded"
        />
      ) : (
        <SplitView inspectorWidth={376}>
          <SplitView.Main>
            <PaneHeader
              meta={`${summaries.filter((provider) => provider.status === "loaded").length} registered`}
              title="Provider surfaces"
            />
            <DataGrid>
              <TableHeader
                columns={["Provider", "Surface", "Routes", "State"]}
                variant="provider"
              />
              {summaries.map((provider) => (
                <DataRow
                  cells={[
                    displaySurfacePath(provider.surfacePath),
                    provider.routeSummary,
                    <ProviderStatus key={`${provider.kind}-state`} provider={provider} />,
                  ]}
                  interactive
                  key={provider.kind}
                  onActivate={() => setSelectedKind(provider.kind)}
                  primary={provider.label}
                  secondary={provider.moduleName}
                  selected={selected?.kind === provider.kind}
                  variant="provider"
                />
              ))}
            </DataGrid>
          </SplitView.Main>
          <SplitView.Inspector>
            {selected ? (
              <ProvidersInspector provider={selected} />
            ) : (
              <ProviderState
                description="No provider Module is available in this Managed Service."
                title="No provider selected"
              />
            )}
          </SplitView.Inspector>
        </SplitView>
      )}
    </ProviderPage>
  );
}

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
  const modulesQuery = useManagedServiceInventory();
  const detail = useMemo(
    () => providerDetail(modulesQuery.data?.modules ?? [], kind),
    [kind, modulesQuery.data?.modules]
  );
  const provider = detail.summary;

  const description =
    kind === "oidc"
      ? "First-party OpenID Connect issuer configuration and protocol endpoints."
      : `${title} sign-in configuration and runtime entry points owned by ${provider?.moduleName ?? `auth-${kind}`}.`;

  return (
    <ProviderPage
      description={description}
      filters={
        kind === "oidc" ? (
          <>
            <ProviderFilter ariaLabel="Endpoint view" value="all">
              <option value="all">All endpoints</option>
            </ProviderFilter>
            <ProviderFilter ariaLabel="Endpoint family" value="protocol">
              <option value="protocol">Discovery + OAuth</option>
            </ProviderFilter>
            <ProviderFilter ariaLabel="Endpoint state" value="registered">
              <option value="registered">Registered</option>
            </ProviderFilter>
          </>
        ) : (
          <>
            <ProviderFilter ariaLabel="Configuration view" value="configuration">
              <option value="configuration">Configuration</option>
            </ProviderFilter>
            <ProviderFilter ariaLabel="Field requirement" value="required">
              <option value="required">Required fields</option>
            </ProviderFilter>
            <ProviderFilter ariaLabel="Configuration source" value="runtime">
              <option value="runtime">Runtime values</option>
            </ProviderFilter>
          </>
        )
      }
      meta="Provider surface · registered"
      title={title}
    >
      {modulesQuery.isPending ? (
        <ProviderState
          description="Reading provider metadata from the selected Managed Service."
          title={`Loading ${title}`}
        />
      ) : modulesQuery.isError ? (
        <ProviderState
          description={errorMessage(modulesQuery.error)}
          title={`${title} could not be loaded`}
        />
      ) : provider ? (
        kind === "oidc" ? (
          <OidcProviderWorkspace provider={provider} routes={detail.routes} />
        ) : (
          <OAuthProviderWorkspace provider={provider} routes={detail.routes} />
        )
      ) : (
        <ProviderState
          description="The provider definition is unavailable."
          title="Provider not found"
        />
      )}
    </ProviderPage>
  );
}

function OAuthProviderWorkspace({
  provider,
  routes,
}: {
  provider: ProviderSummary;
  routes: readonly ModuleHttpRouteLike[];
}) {
  return (
    <SplitView inspectorWidth={376}>
      <SplitView.Main>
        <PaneHeader meta="Module owned" title="Configuration" />
        <DataGrid>
          <TableHeader
            columns={["Field", "Requirement", "Source", "State"]}
          />
          {provider.configuration.map((field) => (
            <DataRow
              cells={[
                field.requirement,
                field.source,
                <InlineStatus key={`${field.name}-state`} tone="success">
                  {field.state}
                </InlineStatus>,
              ]}
              key={field.name}
              primary={field.name}
              secondary={field.description}
              selected={field.name === provider.configuration[0]?.name}
            />
          ))}
          <DataRow
            cells={[
              "Registered",
              provider.moduleName,
              <ProviderStatus key="provider-routes-state" provider={provider} />,
            ]}
            primary="login routes"
            secondary={provider.routeSummary}
          />
        </DataGrid>
      </SplitView.Main>
      <SplitView.Inspector>
        <ProviderDetailInspector provider={provider} routes={routes} />
      </SplitView.Inspector>
    </SplitView>
  );
}

function OidcProviderWorkspace({
  provider,
  routes,
}: {
  provider: ProviderSummary;
  routes: readonly ModuleHttpRouteLike[];
}) {
  const [selectedPath, setSelectedPath] = useState<string | null>(null);
  const selectedRoute =
    routes.find((route) => route.path === selectedPath) ?? routes[0] ?? null;

  return (
    <SplitView inspectorWidth={376}>
      <SplitView.Main>
        <PaneHeader meta={`${routes.length} endpoints`} title="Protocol surface" />
        <DataGrid>
          <TableHeader columns={["Endpoint", "Method", "Purpose", "State"]} />
          {routes.length === 0 ? (
            <ProviderState
              description="The selected Managed Service did not report OIDC routes."
              title="No protocol endpoints"
            />
          ) : (
            routes.map((route) => {
              const description = providerRouteDescription(route);
              return (
                <DataRow
                  cells={[
                    route.method,
                    description.purpose,
                    <ProviderStatus key={`${route.path}-state`} provider={provider} />,
                  ]}
                  interactive
                  key={`${route.method}:${route.path}`}
                  onActivate={() => setSelectedPath(route.path)}
                  primary={route.path}
                  secondary={description.summary}
                  selected={selectedRoute?.path === route.path}
                />
              );
            })
          )}
        </DataGrid>
      </SplitView.Main>
      <SplitView.Inspector>
        <OidcInspector provider={provider} selectedRoute={selectedRoute} />
      </SplitView.Inspector>
    </SplitView>
  );
}

function ProvidersInspector({ provider }: { provider: ProviderSummary }) {
  const [tab, setTab] = useState<ProviderInspectorTab>("overview");
  const state = providerState(provider);

  return (
    <Inspector
      status={<InlineStatus tone={state.tone}>{state.label} surface</InlineStatus>}
      subtitle={provider.moduleName}
      title={provider.label}
    >
      <Tabs density="inspector" stylex={styles.tabs}>
        <Tabs.List>
          <Tabs.Tab onClick={() => setTab("overview")} selected={tab === "overview"}>
            Overview
          </Tabs.Tab>
          <Tabs.Tab
            onClick={() => setTab("configuration")}
            selected={tab === "configuration"}
          >
            Configuration
          </Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel>
          {tab === "overview" ? (
            <>
              <Inspector.Section title="Surface">
                <InspectorLines
                  items={[
                    "Group: Sign-in",
                    `Path: ${displaySurfacePath(provider.surfacePath)}`,
                    "Workspace: Auth",
                  ]}
                />
              </Inspector.Section>
              <Inspector.Section title="Configuration">
                <InspectorLines
                  items={provider.configuration.map((field) => field.name)}
                />
              </Inspector.Section>
              <Inspector.Section title="Operations">
                <InspectorLines
                  items={[
                    ...provider.operations.split(" · "),
                    "Open related stories",
                  ]}
                />
              </Inspector.Section>
              <Inspector.Section title="Ownership">
                <InspectorLines
                  items={[
                    `Routes: ${provider.moduleName}`,
                    "Effects: provider module",
                    "Evidence: runtime inventory",
                  ]}
                />
              </Inspector.Section>
            </>
          ) : (
            <Inspector.Section title="Module-owned fields">
              <KeyValueList>
                {provider.configuration.map((field) => (
                  <KeyValueList.Row
                    key={field.name}
                    label={field.name}
                    value={field.state}
                  />
                ))}
              </KeyValueList>
            </Inspector.Section>
          )}
        </Tabs.Panel>
      </Tabs>
      <Inspector.Actions>
        <Button
          disabled={provider.status === "missing"}
          onClick={() => window.location.assign(provider.surfacePath)}
          variant="primary"
        >
          Open {provider.label}
        </Button>
      </Inspector.Actions>
    </Inspector>
  );
}

function ProviderDetailInspector({
  provider,
  routes,
}: {
  provider: ProviderSummary;
  routes: readonly ModuleHttpRouteLike[];
}) {
  const [tab, setTab] = useState<ProviderInspectorTab>("configuration");
  const state = providerState(provider);

  return (
    <Inspector
      status={
        <InlineStatus tone={state.tone}>
          {state.label} · configuration resolved
        </InlineStatus>
      }
      subtitle={provider.moduleName}
      title={`${provider.label} provider`}
    >
      <Tabs density="inspector" stylex={styles.tabs}>
        <Tabs.List>
          <Tabs.Tab
            onClick={() => setTab("configuration")}
            selected={tab === "configuration"}
          >
            Configuration
          </Tabs.Tab>
          <Tabs.Tab
            onClick={() => setTab("operations")}
            selected={tab === "operations"}
          >
            Operations
          </Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel>
          {tab === "configuration" ? (
            <>
              <Inspector.Section title="Configuration">
                <InspectorLines
                  items={provider.configuration.map((field) => field.name)}
                />
              </Inspector.Section>
              <Inspector.Section title="Sign-in flow">
                <InspectorLines
                  items={[
                    "Start login",
                    "Complete callback",
                    "Session issued by Auth",
                  ]}
                />
              </Inspector.Section>
              <Inspector.Section title="Surface">
                <InspectorLines
                  items={[
                    "Workspace: Auth",
                    "Group: Sign-in",
                    `Surface: ${provider.label}`,
                  ]}
                />
              </Inspector.Section>
              <Inspector.Section title="Evidence">
                <InspectorLines
                  items={[
                    "Secrets never displayed",
                    `Route owner: ${provider.moduleName}`,
                    "Runtime receipts",
                  ]}
                />
              </Inspector.Section>
            </>
          ) : (
            <Inspector.Section title="Registered routes">
              <KeyValueList>
                {routes.map((route) => (
                  <KeyValueList.Row
                    key={`${route.method}:${route.path}`}
                    label={route.method}
                    value={route.path}
                  />
                ))}
              </KeyValueList>
            </Inspector.Section>
          )}
        </Tabs.Panel>
      </Tabs>
      <Inspector.Actions>
        <Button
          disabled
          title="The target-owned sign-in route is not exposed through this Console Surface grant."
          variant="primary"
        >
          Start sign-in
        </Button>
      </Inspector.Actions>
    </Inspector>
  );
}

function OidcInspector({
  provider,
  selectedRoute,
}: {
  provider: ProviderSummary;
  selectedRoute: ModuleHttpRouteLike | null;
}) {
  const [tab, setTab] = useState<ProviderInspectorTab>("operations");
  const state = providerState(provider);
  const routeDescription = selectedRoute
    ? providerRouteDescription(selectedRoute)
    : null;

  return (
    <Inspector
      status={
        <InlineStatus tone={state.tone}>
          {state.label} · protocol surface
        </InlineStatus>
      }
      subtitle={provider.moduleName}
      title="OIDC issuer"
    >
      <Tabs density="inspector" stylex={styles.tabs}>
        <Tabs.List>
          <Tabs.Tab
            onClick={() => setTab("configuration")}
            selected={tab === "configuration"}
          >
            Configuration
          </Tabs.Tab>
          <Tabs.Tab
            onClick={() => setTab("operations")}
            selected={tab === "operations"}
          >
            Endpoints
          </Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel>
          {tab === "configuration" ? (
            <Inspector.Section title="Configuration">
              <InspectorLines
                items={provider.configuration.map((field) => field.name)}
              />
            </Inspector.Section>
          ) : (
            <>
              <Inspector.Section title="Configuration">
                <InspectorLines
                  items={provider.configuration.map((field) => field.name)}
                />
              </Inspector.Section>
              <Inspector.Section title="Selected endpoint">
                <InspectorLines
                  items={[
                    selectedRoute
                      ? `${selectedRoute.method} ${selectedRoute.path}`
                      : "No endpoint selected",
                    routeDescription?.summary ?? "-",
                    "No operator effect",
                  ]}
                />
              </Inspector.Section>
              <Inspector.Section title="Protocol">
                <InspectorLines
                  items={[
                    "Authorization code flow",
                    "JWKS signing keys",
                    "Token exchange",
                  ]}
                />
              </Inspector.Section>
              <Inspector.Section title="Evidence">
                <InspectorLines
                  items={[
                    `Route owner: ${provider.moduleName}`,
                    "Keys remain protected",
                    "Runtime receipts",
                  ]}
                />
              </Inspector.Section>
            </>
          )}
        </Tabs.Panel>
      </Tabs>
      <Inspector.Actions>
        <Button
          disabled
          title="The managed issuer value is not exposed through this Console Surface grant."
        >
          Copy issuer
        </Button>
      </Inspector.Actions>
    </Inspector>
  );
}

function ProviderPage({
  children,
  description,
  filters,
  meta,
  title,
}: {
  children: ReactNode;
  description: ReactNode;
  filters: ReactNode;
  meta: ReactNode;
  title: ReactNode;
}) {
  return (
    <>
      <ConsolePage.Header>
        <ConsolePage.Heading>
          <ConsolePage.Title>{title}</ConsolePage.Title>
          <ConsolePage.Description>{description}</ConsolePage.Description>
        </ConsolePage.Heading>
        <ConsolePage.Actions>{meta}</ConsolePage.Actions>
      </ConsolePage.Header>
      <ConsolePage.Body>
        <div {...stylex.props(pageStyles.pageFilters, styles.filters)}>
          {filters}
        </div>
        {children}
      </ConsolePage.Body>
    </>
  );
}

function ProviderFilter({
  ariaLabel,
  children,
  value,
}: {
  ariaLabel: string;
  children: ReactNode;
  value: string;
}) {
  return (
    <FilterSelect
      aria-label={ariaLabel}
      icon={<span {...stylex.props(styles.filterChevron)}>⌄</span>}
      onChange={() => undefined}
      value={value}
    >
      {children}
    </FilterSelect>
  );
}

function ProviderStatus({ provider }: { provider: ProviderSummary }) {
  const state = providerState(provider);
  return <InlineStatus tone={state.tone}>{state.label}</InlineStatus>;
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

function displaySurfacePath(path: string): string {
  return path.replace(/^\/auth/u, "");
}

function providerState(provider: ProviderSummary): {
  label: "Degraded" | "Missing" | "Registered";
  tone: SemanticTone;
} {
  if (provider.status === "loaded") {
    return { label: "Registered", tone: "success" };
  }
  if (provider.status === "error") {
    return { label: "Degraded", tone: "danger" };
  }
  return { label: "Missing", tone: "neutral" };
}

function ProviderState({
  description,
  title,
}: {
  description: string;
  title: string;
}) {
  return (
    <StateView
      description={description}
      stylex={styles.state}
      title={title}
    />
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
