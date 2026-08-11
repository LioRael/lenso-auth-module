import type {
  ConsoleClient,
  ManagedServiceContext,
  ModuleInventoryModule,
  ModuleInventorySnapshot,
  ResolvedActionContribution,
} from "@lenso/console-module-api";
import { useConsoleClient } from "@lenso/console-ui";
import { useEffect, useState } from "react";

export type ManagedServiceModule = ModuleInventoryModule;
export type ManagedServiceInventory = ModuleInventorySnapshot;
export type ManagedActionContribution = ResolvedActionContribution;

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
  data?: ManagedServiceInventory;
  error: unknown;
  isError: boolean;
  isPending: boolean;
} {
  const client = useConsoleClient();
  const contextKey = contextFingerprint(client.managedServiceContext);
  const [state, setState] = useState<{
    data?: ManagedServiceInventory;
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
  data?: readonly ManagedActionContribution[];
  error: unknown;
  isError: boolean;
  isPending: boolean;
} {
  const client = useConsoleClient();
  const contextKey = contextFingerprint(client.managedServiceContext);
  const [state, setState] = useState<{
    data?: readonly ManagedActionContribution[];
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
