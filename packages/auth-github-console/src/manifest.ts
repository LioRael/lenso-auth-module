import {
  CONSOLE_MODULE_API_PROTOCOL,
  defineConsoleManifest,
} from "@lenso/console-module-api";

export const authGithubConsoleManifest = defineConsoleManifest({
  consoleUi: "^2.0.0",
  hostApi: "^2.1.0",
  moduleId: "lenso/auth-github",
  protocol: CONSOLE_MODULE_API_PROTOCOL,
  surfaces: [
    {
      area: "data",
      icon: "network",
      id: "github-provider",
      label: "GitHub",
      navigation: {
        order: 81,
        workspace: { icon: "shield", id: "auth", label: "Auth" },
      },
      path: "/data/auth/providers/github",
      requiredCapabilities: ["auth.providers.read"],
    },
  ],
});
