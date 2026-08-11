import { defineConsoleUiModule } from "@lenso/console-ui";
import "@lenso/console-ui/stylex.css";

import { AuthSessionsPage, AuthUsersPage } from "./page";
import { authConsoleManifest } from "./manifest";

export const authConsoleUiModule = defineConsoleUiModule({
  manifest: authConsoleManifest,
  surfaces: {
    sessions: AuthSessionsPage,
    users: AuthUsersPage,
  },
});

export { AuthSessionsPage, AuthUsersPage };
export default authConsoleUiModule;
