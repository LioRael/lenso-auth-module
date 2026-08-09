import {
  CONSOLE_MODULE_API_PROTOCOL,
  defineConsoleManifest,
} from "@lenso/console-module-api";

export const authGoogleConsoleManifest = defineConsoleManifest({
  consoleUi: "^2.0.0",
  hostApi: "^1.0.0",
  moduleId: "lenso/auth-google",
  protocol: CONSOLE_MODULE_API_PROTOCOL,
  surfaces: [
    {
      area: "data",
      icon: "network",
      id: "google-provider",
      label: "Google",
      navigation: {
        order: 82,
        workspace: { icon: "shield", id: "auth", label: "Auth" },
      },
      path: "/data/auth/providers/google",
      requiredCapabilities: ["auth.providers.read"],
    },
  ],
});
