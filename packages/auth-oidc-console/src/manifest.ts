import {
  CONSOLE_MODULE_API_PROTOCOL,
  defineConsoleManifest,
} from "@lenso/console-module-api";

export const authOidcConsoleManifest = defineConsoleManifest({
  consoleUi: "^2.0.0",
  hostApi: "^2.1.0",
  moduleId: "lenso/auth-oidc",
  protocol: CONSOLE_MODULE_API_PROTOCOL,
  surfaces: [
    {
      area: "runtime",
      icon: "settings",
      id: "oidc-provider",
      label: "OIDC Provider",
      navigation: {
        group: {
          icon: "git-compare-arrows",
          id: "sign-in",
          label: "Sign-in",
          order: 20,
        },
        order: 83,
        workspace: { icon: "shield", id: "auth", label: "Auth" },
      },
      path: "/auth/providers/oidc",
      requiredCapabilities: ["auth.providers.read"],
    },
  ],
});
