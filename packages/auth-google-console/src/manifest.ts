import {
  CONSOLE_MODULE_API_PROTOCOL,
  defineConsoleManifest,
} from "@lenso/console-module-api";

export const authGoogleConsoleManifest = defineConsoleManifest({
  consoleUi: "^2.0.0",
  hostApi: "^2.1.0",
  moduleId: "lenso/auth-google",
  protocol: CONSOLE_MODULE_API_PROTOCOL,
  surfaces: [
    {
      area: "runtime",
      icon: "chrome",
      id: "google-provider",
      label: "Google",
      navigation: {
        group: {
          icon: "git-compare-arrows",
          id: "sign-in",
          label: "Sign-in",
          order: 20,
        },
        order: 82,
        workspace: { icon: "shield", id: "auth", label: "Auth" },
      },
      path: "/auth/providers/google",
      requiredCapabilities: ["auth.providers.read"],
    },
  ],
});
