import type {
  ConsoleClient,
  ConsoleSha256Digest,
  ManagedServiceContext,
  SurfaceOperationRequest,
} from "@lenso/console-module-api";
import { describe, expect, test } from "vitest";

import {
  AUTH_CONTRACT_DIGEST,
  AUTH_OPERATION_IDS,
  authBusinessApiContract,
  createAuthBusinessApi,
} from "./business-api";

const digest =
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as ConsoleSha256Digest;

const context: ManagedServiceContext = {
  callerModuleId: "lenso/auth",
  capabilities: [
    "auth.sessions.read",
    "auth.sessions.revoke",
    "auth.users.manage",
    "auth.users.read",
  ],
  delegatedActorSubject: "operator-1",
  delegatedAuthorityDigest: digest,
  environmentId: "local",
  serviceId: "my-lenso-app",
  systemId: "my-lenso-system",
  targetServicePrincipal: "svc.my-lenso-app",
};

const fakeClient = (
  requests: SurfaceOperationRequest<unknown>[]
): ConsoleClient => ({
  capabilities: { has: () => true, list: () => context.capabilities },
  identity: {
    moduleId: "lenso/auth",
    moduleReleaseDigest: digest,
    uiArtifactDigest: digest,
  },
  inventory: () => Promise.reject(new Error("unused")),
  managedServiceContext: context,
  navigate: () => {},
  readConfig: () => Promise.reject(new Error("unused")),
  resolveActionContributions: () => Promise.reject(new Error("unused")),
  surfaceApi: {
    invoke: <Input, Output>(request: SurfaceOperationRequest<Input>) => {
      requests.push(request as SurfaceOperationRequest<unknown>);
      return Promise.resolve({
        contractDigest: request.contractDigest,
        moduleId: request.moduleId,
        operationId: request.operationId,
        output: {} as Output,
        protocol: "lenso.console-surface-gateway.v1",
        requestContext: request.requestContext,
      });
    },
  },
  writeConfig: () => Promise.reject(new Error("unused")),
});

describe("Auth Business API client", () => {
  test("invokes read operations through the receipt-bound Surface API", async () => {
    const requests: SurfaceOperationRequest<unknown>[] = [];
    const api = createAuthBusinessApi(fakeClient(requests));

    await api.listUsers({ cursor: "usr_1", limit: 50 });
    await api.listSessions({ limit: 200 });

    expect(requests).toMatchObject([
      {
        contractDigest: AUTH_CONTRACT_DIGEST,
        input: { cursor: "usr_1", limit: 50 },
        moduleId: "lenso/auth",
        operationId: AUTH_OPERATION_IDS.listUsers,
      },
      {
        contractDigest: AUTH_CONTRACT_DIGEST,
        input: { limit: 200 },
        operationId: AUTH_OPERATION_IDS.listSessions,
      },
    ]);
    expect(requests[0]).not.toHaveProperty("url");
    expect(requests[0]).not.toHaveProperty("method");
    expect(requests[0]?.requestContext.deadlineUnixMs).toBeGreaterThan(
      Date.now()
    );
  });

  test("keeps each Auth mutation as a stable contract operation", async () => {
    const requests: SurfaceOperationRequest<unknown>[] = [];
    const api = createAuthBusinessApi(fakeClient(requests));

    await api.disableUser("usr_1", {
      disabled_until: "2026-08-12T12:00:00.000Z",
      reason: "review",
    });
    await api.enableUser("usr_1");
    await api.revokeSession("sess_1");

    expect(requests).toMatchObject([
      {
        input: {
          disabled_until: "2026-08-12T12:00:00.000Z",
          reason: "review",
          userId: "usr_1",
        },
        operationId: AUTH_OPERATION_IDS.disableUser,
      },
      {
        input: { userId: "usr_1" },
        operationId: AUTH_OPERATION_IDS.enableUser,
      },
      {
        input: { sessionId: "sess_1" },
        operationId: AUTH_OPERATION_IDS.revokeSession,
      },
    ]);
    expect(
      authBusinessApiContract.paths["/users/{userId}/disable"].post.operationId
    ).toBe(AUTH_OPERATION_IDS.disableUser);
  });
});
