import {
  CONSOLE_MODULE_API_PROTOCOL,
  defineConsoleManifest,
} from "@lenso/console-module-api";

export const authOauthConsoleManifest = defineConsoleManifest({
  consoleUi: "^2.0.0",
  hostApi: "^2.1.0",
  moduleId: "lenso/auth-oauth",
  protocol: CONSOLE_MODULE_API_PROTOCOL,
  surfaces: [
    {
      area: "data",
      icon: "network",
      id: "providers",
      label: "Providers",
      navigation: {
        order: 80,
        workspace: { icon: "shield", id: "auth", label: "Auth" },
      },
      path: "/data/auth/providers",
      requiredCapabilities: ["auth.providers.read"],
    },
  ],
});
