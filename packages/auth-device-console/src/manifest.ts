import {
  CONSOLE_MODULE_API_PROTOCOL,
  defineConsoleManifest,
} from "@lenso/console-module-api";

export const authDeviceConsoleManifest = defineConsoleManifest({
  consoleUi: "^2.0.0",
  hostApi: "^2.1.0",
  moduleId: "lenso/auth-device",
  protocol: CONSOLE_MODULE_API_PROTOCOL,
  surfaces: [
    {
      area: "runtime",
      icon: "smartphone",
      id: "devices",
      label: "Devices",
      navigation: {
        group: {
          icon: "users",
          id: "directory",
          label: "Directory",
          order: 10,
        },
        order: 70,
        workspace: { icon: "shield", id: "auth", label: "Auth" },
      },
      path: "/auth/devices",
      requiredCapabilities: ["auth_device.devices.read"],
    },
  ],
});
