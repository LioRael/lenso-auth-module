import type {
  ConsoleClient,
  ConsoleRecord,
  ConsoleRecordPage,
} from "@lenso/console-module-api";
import { consoleCommands, consoleQueries } from "@lenso/console-module-api";
import {
  useConsoleClient,
  useConsoleCommand,
  useConsoleQuery,
} from "@lenso/console-ui";
import { useCallback, useEffect, useMemo, useState } from "react";

export type ConsoleRecordPageState = {
  data?: ConsoleRecordPage | undefined;
  error: unknown;
  isError: boolean;
  isPending: boolean;
};

export function useConsoleRecords(entity: string): ConsoleRecordPageState {
  managedServiceContextClient(useConsoleClient());
  const operation = useMemo(
    () => consoleQueries.records({ entity, limit: 200 }),
    [entity]
  );
  const query = useConsoleQuery<ConsoleRecordPage>(operation);
  return {
    data: query.status === "success" ? query.data : undefined,
    error: query.status === "error" ? query.error : null,
    isError: query.status === "error",
    isPending: query.status === "pending",
  };
}

export type ConsoleActionRequest = {
  actionName: string;
  input: Record<string, unknown>;
  moduleName: string;
};

export type ConsoleActionState = {
  error: unknown;
  isError: boolean;
  isPending: boolean;
  mutate: (request: ConsoleActionRequest) => void;
};

export function useConsoleAction(): ConsoleActionState {
  managedServiceContextClient(useConsoleClient());
  const [request, setRequest] = useState<ConsoleActionRequest | null>(null);
  const [state, setState] = useState<Omit<ConsoleActionState, "mutate">>({
    error: null,
    isError: false,
    isPending: false,
  });
  const factory = useMemo(
    () =>
      consoleCommands.action<Record<string, unknown>, unknown>(
        request?.actionName ?? "__lenso_auth_action_idle__"
      ),
    [request?.actionName]
  );
  const input = useMemo(
    () =>
      request
        ? { ...request.input, module: request.moduleName }
        : ({} as Record<string, unknown>),
    [request]
  );
  const command = useConsoleCommand(factory, input);

  useEffect(() => {
    if (!request) {
      return;
    }
    void command
      .execute()
      .then(() => {
        setState({ error: null, isError: false, isPending: false });
      })
      .catch((error: unknown) => {
        setState({ error, isError: true, isPending: false });
      })
      .finally(() => {
        setRequest(null);
      });
  }, [command.execute, request]);

  const mutate = useCallback(
    (request: ConsoleActionRequest) => {
      setState({ error: null, isError: false, isPending: true });
      setRequest(request);
    },
    []
  );
  return { ...state, mutate };
}

export type ManagedServiceContext = {
  readonly systemId: string;
  readonly serviceId: string;
  readonly environmentId: string;
  readonly targetServicePrincipal: string;
  readonly callerModuleId: string;
  readonly delegatedActorSubject: string;
  readonly delegatedAuthorityDigest: `sha256:${string}`;
  readonly capabilities: readonly string[];
};

export type ManagedServiceModule = {
  readonly moduleId: string;
  readonly version: string;
  readonly releaseDigest: `sha256:${string}`;
  readonly manifestDigest: `sha256:${string}`;
  readonly delivery: "linked" | "service";
  readonly dependencyModuleIds?: readonly string[];
  readonly routes?: readonly {
    readonly method: string;
    readonly path: string;
    readonly capability?: string;
  }[];
  readonly runtimeFunctions?: readonly string[];
  readonly runtimeStatus: "active" | "disabled" | "degraded" | "failed";
  readonly consoleUi?: {
    readonly format: "console_ui_esm";
    readonly protocolMajor: number;
    readonly artifactDigest: `sha256:${string}`;
    readonly entry: string;
    readonly styleAssets?: readonly string[];
  };
};

export type ManagedServiceInventory = {
  readonly modules: readonly ManagedServiceModule[];
};

export type ManagedActionContribution = {
  readonly contributingModuleId: string;
  readonly target: string;
  readonly targetVersion: number;
  readonly label: string;
  readonly action: {
    readonly kind: "admin_action";
    readonly module: string;
    readonly name: string;
    readonly inputBindings?: readonly {
      readonly input: string;
      readonly value: { readonly kind: "slot_context"; readonly path: string };
    }[];
  };
  readonly icon?: string;
  readonly requiredCapabilities?: readonly string[];
};

type ManagedServiceClient = ConsoleClient & {
  readonly managedServiceContext: ManagedServiceContext;
  inventory: (request: {
    readonly context: ManagedServiceContext;
  }) => Promise<ManagedServiceInventory>;
  resolveActionContributions: (request: {
    readonly context: ManagedServiceContext;
    readonly slot: string;
    readonly slotVersion: number;
    readonly slotContext?: Readonly<Record<string, unknown>>;
  }) => Promise<{ readonly contributions: readonly ManagedActionContribution[] }>;
};

type ContextBoundConsoleClient = ConsoleClient & {
  readonly managedServiceContext: ManagedServiceContext;
};

function managedServiceContextClient(
  client: ConsoleClient
): ContextBoundConsoleClient {
  const candidate = client as ConsoleClient &
    Partial<ContextBoundConsoleClient>;
  if (!candidate.managedServiceContext) {
    throw new Error(
      "The Console host did not bind this surface to a Managed Service Context"
    );
  }
  return candidate as ContextBoundConsoleClient;
}

function managedServiceClient(client: ConsoleClient): ManagedServiceClient {
  const candidate = managedServiceContextClient(client) as ConsoleClient &
    Partial<ManagedServiceClient>;
  if (
    !candidate.managedServiceContext ||
    typeof candidate.inventory !== "function" ||
    typeof candidate.resolveActionContributions !== "function"
  ) {
    throw new Error(
      "The Console host does not provide the verified Managed Service Context contract"
    );
  }
  return candidate as ManagedServiceClient;
}

function contextFingerprint(context: ManagedServiceContext): string {
  return JSON.stringify([
    context.systemId,
    context.serviceId,
    context.environmentId,
    context.targetServicePrincipal,
    context.callerModuleId,
    context.delegatedActorSubject,
    context.delegatedAuthorityDigest,
    context.capabilities,
  ]);
}

export function useManagedServiceInventory(): {
  data?: ManagedServiceInventory | undefined;
  error: unknown;
  isError: boolean;
  isPending: boolean;
} {
  const client = managedServiceClient(useConsoleClient());
  const contextKey = contextFingerprint(client.managedServiceContext);
  const [state, setState] = useState<{
    data?: ManagedServiceInventory | undefined;
    error: unknown;
    isError: boolean;
    isPending: boolean;
  }>({ error: null, isError: false, isPending: true });

  useEffect(() => {
    let active = true;
    setState({ error: null, isError: false, isPending: true });
    void client
      .inventory({ context: client.managedServiceContext })
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

export function useUserActionContributions(userId: string | null): {
  data?: readonly ManagedActionContribution[] | undefined;
  error: unknown;
  isError: boolean;
  isPending: boolean;
} {
  const client = managedServiceClient(useConsoleClient());
  const contextKey = contextFingerprint(client.managedServiceContext);
  const [state, setState] = useState<{
    data?: readonly ManagedActionContribution[] | undefined;
    error: unknown;
    isError: boolean;
    isPending: boolean;
  }>({ data: [], error: null, isError: false, isPending: false });

  useEffect(() => {
    if (!userId) {
      setState({ data: [], error: null, isError: false, isPending: false });
      return;
    }
    let active = true;
    setState({ error: null, isError: false, isPending: true });
    void client
      .resolveActionContributions({
        context: client.managedServiceContext,
        slot: "auth.users.detail.actions",
        slotContext: { selected_user: { id: userId } },
        slotVersion: 1,
      })
      .then((response) => {
        if (active) {
          setState({
            data: response.contributions,
            error: null,
            isError: false,
            isPending: false,
          });
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
  }, [client, contextKey, userId]);

  return state;
}

export function hasCapabilities(
  client: ConsoleClient,
  required: readonly string[] | undefined
): boolean {
  return (required ?? []).every((capability) =>
    client.capabilities.has(capability)
  );
}

export function consoleRecordData(
  page: ConsoleRecordPage | undefined
): readonly ConsoleRecord[] {
  return page?.data ?? [];
}
