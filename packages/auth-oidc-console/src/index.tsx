import { defineConsoleUiModule, ConsolePage, SurfaceRoot } from "@lenso/console-ui";

import { OidcProviderPage } from "@lenso/auth-provider-console-ui";
import "./styles.css";
import { authOidcConsoleManifest } from "./manifest";

const OidcSurface = () => (
  <SurfaceRoot moduleId="lenso/auth-oidc" surfaceId="oidc-provider">
    <ConsolePage scroll={false}>
      <OidcProviderPage />
    </ConsolePage>
  </SurfaceRoot>
);

const authOidcConsoleUiModule = defineConsoleUiModule({
  manifest: authOidcConsoleManifest,
  surfaces: { "oidc-provider": OidcSurface },
});

export default authOidcConsoleUiModule;
