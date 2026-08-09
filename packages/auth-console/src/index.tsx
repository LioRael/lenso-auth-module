import { defineConsoleUiModule } from "@lenso/console-ui";

import "./styles.css";
import { AuthSessionsPage, AuthUsersPage } from "./page";
import { authConsoleManifest } from "./manifest";

const authConsoleUiModule = defineConsoleUiModule({
  manifest: authConsoleManifest,
  surfaces: {
    sessions: AuthSessionsPage,
    users: AuthUsersPage,
  },
});

export { AuthSessionsPage, AuthUsersPage };
export default authConsoleUiModule;
