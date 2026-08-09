import { defineConsoleUiModule, ConsolePage, SurfaceRoot } from "@lenso/console-ui";

import { AuthProvidersPage } from "@lenso/auth-provider-console-ui";
import "./styles.css";
import { authOauthConsoleManifest } from "./manifest";

const ProvidersSurface = () => (
  <SurfaceRoot moduleId="lenso/auth-oauth" surfaceId="providers">
    <ConsolePage scroll={false}>
      <AuthProvidersPage />
    </ConsolePage>
  </SurfaceRoot>
);

const authOauthConsoleUiModule = defineConsoleUiModule({
  manifest: authOauthConsoleManifest,
  surfaces: { providers: ProvidersSurface },
});

export default authOauthConsoleUiModule;
