import type {
  ConsoleClient,
  SurfaceOperationRequestContext,
} from "@lenso/console-module-api";

import contract from "./auth-business-api.v1.json";

export const AUTH_CONTRACT_DIGEST =
  "sha256:b57f7626fb6eac67b0595c17894671f08782ec4ca7d8c69990769048570999ed" as const;

export const AUTH_OPERATION_IDS = {
  disableUser: "auth/http/POST:/users/{id}/disable",
  enableUser: "auth/http/POST:/users/{id}/enable",
  listSessions: "auth/http/GET:/sessions",
  listUsers: "auth/http/GET:/users",
  revokeSession: "auth/http/POST:/sessions/{id}/revoke",
} as const;

export interface AuthUserRecord {
  readonly id: string;
  readonly is_anonymous: boolean;
  readonly created_at: string;
  readonly disabled_at: string | null;
  readonly disabled_reason: string | null;
  readonly disabled_until: string | null;
}

export interface AuthSessionRecord {
  readonly id: string;
  readonly user_id: string;
  readonly device_id: string | null;
  readonly client_ip: string | null;
  readonly user_agent: string | null;
  readonly created_at: string;
  readonly expires_at: string;
  readonly revoked_at: string | null;
}

export interface AuthPage<Record> {
  readonly records: readonly Record[];
  readonly next_cursor: string | null;
}

export interface AuthListInput {
  readonly limit?: number;
  readonly cursor?: string;
}

export interface DisableAuthUserInput {
  readonly reason?: string;
  readonly disabled_until?: string;
}

export interface AuthUserMutationResult {
  readonly user_id: string;
  readonly changed: boolean;
}

export interface AuthSessionMutationResult {
  readonly session_id: string;
  readonly revoked: boolean;
}

export interface AuthRequestOptions {
  readonly tenantId?: string;
  readonly deadlineUnixMs?: number;
  readonly story?: SurfaceOperationRequestContext["story"];
}

export interface AuthBusinessApi {
  listUsers(
    input?: AuthListInput,
    options?: AuthRequestOptions
  ): Promise<AuthPage<AuthUserRecord>>;
  listSessions(
    input?: AuthListInput,
    options?: AuthRequestOptions
  ): Promise<AuthPage<AuthSessionRecord>>;
  disableUser(
    userId: string,
    input?: DisableAuthUserInput,
    options?: AuthRequestOptions
  ): Promise<AuthUserMutationResult>;
  enableUser(
    userId: string,
    options?: AuthRequestOptions
  ): Promise<AuthUserMutationResult>;
  revokeSession(
    sessionId: string,
    options?: AuthRequestOptions
  ): Promise<AuthSessionMutationResult>;
}

const createRequestContext = (
  options: AuthRequestOptions | undefined
): SurfaceOperationRequestContext => ({
  ...(options?.tenantId ? { tenantId: options.tenantId } : {}),
  deadlineUnixMs: options?.deadlineUnixMs ?? Date.now() + 10_000,
  ...(options?.story ? { story: options.story } : {}),
});

export const createAuthBusinessApi = (
  client: ConsoleClient
): AuthBusinessApi => {
  const invoke = async <Input, Output>(
    operationId: string,
    input: Input,
    options?: AuthRequestOptions
  ): Promise<Output> => {
    const response = await client.surfaceApi.invoke<Input, Output>({
      context: client.managedServiceContext,
      contractDigest: AUTH_CONTRACT_DIGEST,
      input,
      moduleId: client.identity.moduleId,
      moduleReleaseDigest: client.identity.moduleReleaseDigest,
      operationId,
      protocol: "lenso.console-surface-gateway.v1",
      requestContext: createRequestContext(options),
      uiArtifactDigest: client.identity.uiArtifactDigest,
    });
    return response.output;
  };

  return {
    disableUser: (userId, input, options) =>
      invoke(
        AUTH_OPERATION_IDS.disableUser,
        { userId, ...(input ?? {}) },
        options
      ),
    enableUser: (userId, options) =>
      invoke(AUTH_OPERATION_IDS.enableUser, { userId }, options),
    listSessions: (input, options) =>
      invoke(AUTH_OPERATION_IDS.listSessions, input ?? {}, options),
    listUsers: (input, options) =>
      invoke(AUTH_OPERATION_IDS.listUsers, input ?? {}, options),
    revokeSession: (sessionId, options) =>
      invoke(AUTH_OPERATION_IDS.revokeSession, { sessionId }, options),
  };
};

export const authBusinessApiContract = contract;
