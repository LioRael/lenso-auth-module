import {
  CONSOLE_MODULE_API_PROTOCOL,
  defineConsoleManifest,
} from "@lenso/console-module-api";

export const authDeviceConsoleManifest = defineConsoleManifest({
  consoleUi: "^2.0.0",
  hostApi: "^1.0.0",
  moduleId: "lenso/auth-device",
  protocol: CONSOLE_MODULE_API_PROTOCOL,
  surfaces: [
    {
      area: "data",
      icon: "network",
      id: "devices",
      label: "Devices",
      navigation: {
        order: 70,
        workspace: { icon: "shield", id: "auth", label: "Auth" },
      },
      path: "/data/auth/devices",
      requiredCapabilities: ["auth_device.devices.read"],
    },
  ],
});
