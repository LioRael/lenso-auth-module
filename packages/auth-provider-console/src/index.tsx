import { defineConsoleModule } from "@lenso/runtime-console-api";

import "./styles.css";
import { authProviderConsoleManifest } from "./manifest";
import {
  AuthProvidersPage,
  GitHubProviderPage,
  GoogleProviderPage,
  OidcProviderPage,
} from "./page";

const surfaces = Object.fromEntries(
  authProviderConsoleManifest.surfaces.map((surface) => [
    surface.surfaceName,
    surface,
  ])
);

export const authProviderConsoleModule = defineConsoleModule({
  id: authProviderConsoleManifest.id,
  surfaces: [
    {
      area: surfaces.providers!.area,
      component: AuthProvidersPage,
      icon: surfaces.providers!.icon,
      label: surfaces.providers!.label,
      navigation: surfaces.providers!.navigation,
      path: surfaces.providers!.route,
    },
    {
      area: surfaces.github!.area,
      component: GitHubProviderPage,
      icon: surfaces.github!.icon,
      label: surfaces.github!.label,
      navigation: surfaces.github!.navigation,
      path: surfaces.github!.route,
    },
    {
      area: surfaces.google!.area,
      component: GoogleProviderPage,
      icon: surfaces.google!.icon,
      label: surfaces.google!.label,
      navigation: surfaces.google!.navigation,
      path: surfaces.google!.route,
    },
    {
      area: surfaces.oidc!.area,
      component: OidcProviderPage,
      icon: surfaces.oidc!.icon,
      label: surfaces.oidc!.label,
      navigation: surfaces.oidc!.navigation,
      path: surfaces.oidc!.route,
    },
  ],
});

export { authProviderConsoleManifest } from "./manifest";
export {
  AuthProvidersPage,
  GitHubProviderPage,
  GoogleProviderPage,
  OidcProviderPage,
} from "./page";
