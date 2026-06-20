import { defineConsoleModule } from "@lenso/runtime-console-api";

import "./styles.css";
import { authConsoleManifest } from "./manifest";
import { AuthSessionsPage, AuthUsersPage } from "./page";

const legacySurface = authConsoleManifest.surfaces.find(
  (surface) => surface.surfaceName === "auth"
)!;
const sessionsSurface = authConsoleManifest.surfaces.find(
  (surface) => surface.surfaceName === "sessions"
)!;
const usersSurface = authConsoleManifest.surfaces.find(
  (surface) => surface.surfaceName === "users"
)!;

export const authConsoleModule = defineConsoleModule({
  id: authConsoleManifest.id,
  surfaces: [
    {
      area: legacySurface.area,
      component: AuthSessionsPage,
      icon: legacySurface.icon,
      label: legacySurface.label,
      navigation: legacySurface.navigation,
      path: legacySurface.route,
    },
    {
      area: sessionsSurface.area,
      component: AuthSessionsPage,
      icon: sessionsSurface.icon,
      label: sessionsSurface.label,
      navigation: sessionsSurface.navigation,
      path: sessionsSurface.route,
    },
    {
      area: usersSurface.area,
      component: AuthUsersPage,
      icon: usersSurface.icon,
      label: usersSurface.label,
      navigation: usersSurface.navigation,
      path: usersSurface.route,
    },
  ],
});

export { authConsoleManifest } from "./manifest";
export { AuthSessionsPage, AuthUsersPage } from "./page";
