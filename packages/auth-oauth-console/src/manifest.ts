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
      area: "runtime",
      icon: "blocks",
      id: "providers",
      label: "Providers",
      navigation: {
        group: {
          icon: "git-compare-arrows",
          id: "sign-in",
          label: "Sign-in",
          order: 20,
        },
        order: 80,
        workspace: { icon: "shield", id: "auth", label: "Auth" },
      },
      path: "/auth/providers",
      requiredCapabilities: ["auth.providers.read"],
    },
  ],
});
