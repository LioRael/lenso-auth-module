import {
  CONSOLE_MODULE_API_PROTOCOL,
  defineConsoleManifest,
} from "@lenso/console-module-api";

export const authConsoleManifest = defineConsoleManifest({
  consoleUi: "^2.0.0",
  hostApi: "^2.1.0",
  moduleId: "lenso/auth",
  protocol: CONSOLE_MODULE_API_PROTOCOL,
  surfaces: [
    {
      area: "runtime",
      icon: "shield",
      id: "sessions",
      label: "Sessions",
      navigation: {
        group: { id: "directory", label: "Directory", order: 10 },
        order: 60,
        workspace: { icon: "shield", id: "auth", label: "Auth" },
      },
      path: "/auth/sessions",
      requiredCapabilities: ["auth.sessions.read"],
    },
    {
      area: "runtime",
      icon: "shield",
      id: "users",
      label: "Users",
      navigation: {
        group: { id: "directory", label: "Directory", order: 10 },
        order: 50,
        workspace: { icon: "shield", id: "auth", label: "Auth" },
      },
      path: "/auth/users",
      requiredCapabilities: ["auth.users.read"],
    },
  ],
});
