import { defineConsoleUiModule } from "@lenso/console-ui";

import "./styles.css";
import { AuthDevicesPage } from "./page";
import { authDeviceConsoleManifest } from "./manifest";

const authDeviceConsoleUiModule = defineConsoleUiModule({
  manifest: authDeviceConsoleManifest,
  surfaces: { devices: AuthDevicesPage },
});

export { AuthDevicesPage };
export default authDeviceConsoleUiModule;
