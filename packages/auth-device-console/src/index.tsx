import { defineConsoleModule } from "@lenso/runtime-console-api";

import "./styles.css";
import { authDeviceConsoleManifest } from "./manifest";
import { AuthDevicesPage } from "./page";

const devicesSurface = authDeviceConsoleManifest.surfaces.find(
  (surface) => surface.surfaceName === "devices"
)!;

export const authDeviceConsoleModule = defineConsoleModule({
  id: authDeviceConsoleManifest.id,
  surfaces: [
    {
      area: devicesSurface.area,
      component: AuthDevicesPage,
      icon: devicesSurface.icon,
      label: devicesSurface.label,
      navigation: devicesSurface.navigation,
      path: devicesSurface.route,
    },
  ],
});

export { authDeviceConsoleManifest } from "./manifest";
export { AuthDevicesPage } from "./page";
