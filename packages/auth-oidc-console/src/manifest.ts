import {
  CONSOLE_MODULE_API_PROTOCOL,
  defineConsoleManifest,
} from "@lenso/console-module-api";

export const authOidcConsoleManifest = defineConsoleManifest({
  consoleUi: "^2.0.0",
  hostApi: "^1.0.0",
  moduleId: "lenso/auth-oidc",
  protocol: CONSOLE_MODULE_API_PROTOCOL,
  surfaces: [
    {
      area: "data",
      icon: "shield",
      id: "oidc-provider",
      label: "OIDC Provider",
      navigation: {
        order: 83,
        workspace: { icon: "shield", id: "auth", label: "Auth" },
      },
      path: "/data/auth/providers/oidc",
      requiredCapabilities: ["auth.providers.read"],
    },
  ],
});
