import { connectConsoleBridge, type ConsoleBridgeClient } from "@lenso/console-bridge";
import { useCallback, useEffect, useState } from "react";

type QueryState<T> = {
  data?: T;
  error: unknown;
  isError: boolean;
  isPending: boolean;
};

type MutationState = {
  error: unknown;
  isError: boolean;
  isPending: boolean;
  mutate: (request: Record<string, unknown>) => void;
};

let bridge: Promise<ConsoleBridgeClient> | undefined;

export function configureConsoleBridge(moduleId: string, surface: string) {
  bridge = connectConsoleBridge({ moduleId, surface });
}

function client(): Promise<ConsoleBridgeClient> {
  if (!bridge) {
    return Promise.reject(new Error("Console Bridge is not configured"));
  }
  return bridge;
}

function useBridgeQuery<T>(permission: string, payload: unknown): QueryState<T> {
  const [state, setState] = useState<QueryState<T>>({
    error: null,
    isError: false,
    isPending: true,
  });
  const serialized = JSON.stringify(payload);
  useEffect(() => {
    let active = true;
    setState({ error: null, isError: false, isPending: true });
    void client()
      .then((value) => value.request<{ data: T }>(permission, payload))
      .then((response) => {
        if (active) {
          setState({ data: response.data, error: null, isError: false, isPending: false });
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
  }, [permission, serialized]);
  return state;
}

function useBridgeMutation(
  permissionFor: (request: Record<string, unknown>) => string,
  payloadFor: (request: Record<string, unknown>) => unknown
): MutationState {
  const [state, setState] = useState<Omit<MutationState, "mutate">>({
    error: null,
    isError: false,
    isPending: false,
  });
  const mutate = useCallback((request: Record<string, unknown>) => {
    setState({ error: null, isError: false, isPending: true });
    void client()
      .then((value) => value.request(permissionFor(request), payloadFor(request)))
      .then(() => setState({ error: null, isError: false, isPending: false }))
      .catch((error: unknown) => setState({ error, isError: true, isPending: false }));
  }, []);
  return { ...state, mutate };
}

const entityPermissions: Record<string, string> = {
  "auth:users": "auth.users.read",
  "auth:sessions": "auth.users.read",
  "auth-device:devices": "auth_device.devices.read",
};

const actionPermissions: Record<string, string> = {
  disable_user: "auth.users.manage",
  enable_user: "auth.users.manage",
  reset_password: "auth_password.credentials.write",
  revoke_session: "auth.users.manage",
};

function requiredPermission(value: string | undefined, operation: string): string {
  if (!value) {
    throw new Error(`Console permission is not declared for ${operation}`);
  }
  return value;
}

export const consoleHostApi = {
  adminData: {
    useRecords(input: { entityName: string; moduleName: string }) {
      const permission = requiredPermission(
        entityPermissions[`${input.moduleName}:${input.entityName}`],
        `${input.moduleName}:${input.entityName}`
      );
      return useBridgeQuery<{ data: Record<string, unknown>[] }>(permission, {
        operation: "admin_data_list",
        entity: input.entityName,
        limit: 200,
      });
    },
    useInvokeAction() {
      return useBridgeMutation(
        (request) => requiredPermission(
          actionPermissions[String(request.actionName)],
          String(request.actionName)
        ),
        (request) => ({
          operation: "admin_action_invoke",
          action: request.actionName,
          input: request.input ?? {},
        })
      );
    },
  },
  config: {
    useValues() {
      return useBridgeQuery<{ data: Record<string, unknown>[] }>("auth.users.manage", {
        operation: "config_values",
      });
    },
    useWriteValue() {
      return useBridgeMutation(
        () => "auth.users.manage",
        (request) => ({ operation: "config_write", ...request })
      );
    },
  },
  contributions: {
    useSlot(target: string, context: Record<string, unknown>) {
      const query = useBridgeQuery<{ data: Record<string, unknown>[] }>("auth.users.manage", {
        operation: "contributions_resolve",
        target,
        context,
      });
      return query.data?.data ?? [];
    },
  },
  modules: {
    useMetadata() {
      return useBridgeQuery<{ modules: Record<string, unknown>[] }>(
        "auth.providers.read",
        { operation: "modules_metadata" }
      );
    },
  },
};
