import type { ConsoleClient } from "@lenso/console-module-api";

export const AUTH_DEVICE_CONTRACT_DIGEST =
  "sha256:89fc2a46836cb0bb3d7831276d20d37923ff63be3e04087b6d38866fbd14b052" as const;
export const AUTH_DEVICE_LIST_OPERATION =
  "auth-device/http/GET:/devices" as const;

export interface AuthDeviceRecord {
  readonly id: string;
  readonly user_id: string;
  readonly created_at: string;
  readonly updated_at: string;
  readonly trusted_at: string | null;
  readonly primary_at: string | null;
  readonly last_seen_ip: string | null;
  readonly last_seen_user_agent: string | null;
}

export interface AuthDevicePage {
  readonly records: readonly AuthDeviceRecord[];
  readonly next_cursor: string | null;
}

export const listAuthDevices = (
  client: ConsoleClient,
  input: { readonly limit?: number; readonly cursor?: string } = {}
): Promise<AuthDevicePage> =>
  client.surfaceApi
    .invoke<typeof input, AuthDevicePage>({
      context: client.managedServiceContext,
      contractDigest: AUTH_DEVICE_CONTRACT_DIGEST,
      input,
      moduleId: client.identity.moduleId,
      moduleReleaseDigest: client.identity.moduleReleaseDigest,
      operationId: AUTH_DEVICE_LIST_OPERATION,
      protocol: "lenso.console-surface-gateway.v1",
      requestContext: { deadlineUnixMs: Date.now() + 10_000 },
      uiArtifactDigest: client.identity.uiArtifactDigest,
    })
    .then((response) => response.output);
