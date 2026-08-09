import {
  CONSOLE_MODULE_API_PROTOCOL,
  defineConsoleManifest,
} from "@lenso/console-module-api";

export const authConsoleManifest = defineConsoleManifest({
  consoleUi: "^2.0.0",
  hostApi: "^1.0.0",
  moduleId: "lenso/auth",
  protocol: CONSOLE_MODULE_API_PROTOCOL,
  surfaces: [
    {
      area: "data",
      icon: "shield",
      id: "sessions",
      label: "Sessions",
      navigation: {
        order: 50,
        workspace: { icon: "shield", id: "auth", label: "Auth" },
      },
      path: "/data/auth/sessions",
      requiredCapabilities: ["auth.sessions.read"],
    },
    {
      area: "data",
      icon: "shield",
      id: "users",
      label: "Users",
      navigation: {
        order: 60,
        workspace: { icon: "shield", id: "auth", label: "Auth" },
      },
      path: "/data/auth/users",
      requiredCapabilities: ["auth.users.read"],
    },
  ],
});
