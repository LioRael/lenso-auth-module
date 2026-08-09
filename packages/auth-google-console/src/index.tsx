import { defineConsoleUiModule, ConsolePage, SurfaceRoot } from "@lenso/console-ui";

import { GoogleProviderPage } from "@lenso/auth-provider-console-ui";
import "./styles.css";
import { authGoogleConsoleManifest } from "./manifest";

const GoogleSurface = () => (
  <SurfaceRoot moduleId="lenso/auth-google" surfaceId="google-provider">
    <ConsolePage scroll={false}>
      <GoogleProviderPage />
    </ConsolePage>
  </SurfaceRoot>
);

const authGoogleConsoleUiModule = defineConsoleUiModule({
  manifest: authGoogleConsoleManifest,
  surfaces: { "google-provider": GoogleSurface },
});

export default authGoogleConsoleUiModule;
