export type ConsoleSurfaceArea = string;
export type ConsoleSurfaceIcon = string;

export interface ConsoleWorkspaceRef {
  id: string;
  label: string;
  icon?: ConsoleSurfaceIcon;
}

export interface ConsoleNavigationMetadata {
  order?: number;
  workspace?: ConsoleWorkspaceRef;
}

export interface ConsoleModuleSurface {
  area: ConsoleSurfaceArea;
  component: unknown;
  icon?: ConsoleSurfaceIcon;
  label: string;
  navigation?: ConsoleNavigationMetadata;
  path: string;
}

export interface ConsoleModule {
  id: string;
  surfaces: readonly ConsoleModuleSurface[];
}

export type ConsoleAdminRecord = Record<string, unknown>;

export interface ConsoleAdminListResponse {
  data: readonly ConsoleAdminRecord[];
}

export interface ConsoleAdminQueryResult {
  data?: ConsoleAdminListResponse;
  error: unknown;
  isError: boolean;
  isPending: boolean;
}

export interface ConsoleAdminActionRequest {
  actionName: string;
  input?: Record<string, unknown>;
  moduleName: string;
}

export interface ConsoleAdminActionMutation {
  error: unknown;
  isError: boolean;
  isPending: boolean;
  mutate: (request: ConsoleAdminActionRequest) => void;
}

export interface RuntimeConsoleHostApi {
  adminData: {
    useInvokeAction: () => ConsoleAdminActionMutation;
    useRecords: (request: {
      entityName: string;
      moduleName: string;
    }) => ConsoleAdminQueryResult;
  };
}

export const defineConsoleModule = <Module extends ConsoleModule>(
  module: Module
): Module => module;

export const defineConsolePackageManifest = <Manifest>(
  manifest: Manifest
): Manifest => manifest;

const missingHostApi = () => {
  throw new Error("Runtime Console host API shim is not executable.");
};

export const runtimeConsoleHostApi: RuntimeConsoleHostApi = {
  adminData: {
    useInvokeAction: missingHostApi,
    useRecords: missingHostApi,
  },
};
