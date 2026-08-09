import { defineConsoleUiModule, ConsolePage, SurfaceRoot } from "@lenso/console-ui";

import { GitHubProviderPage } from "@lenso/auth-provider-console-ui";
import "./styles.css";
import { authGithubConsoleManifest } from "./manifest";

const GitHubSurface = () => (
  <SurfaceRoot moduleId="lenso/auth-github" surfaceId="github-provider">
    <ConsolePage scroll={false}>
      <GitHubProviderPage />
    </ConsolePage>
  </SurfaceRoot>
);

const authGithubConsoleUiModule = defineConsoleUiModule({
  manifest: authGithubConsoleManifest,
  surfaces: { "github-provider": GitHubSurface },
});

export default authGithubConsoleUiModule;
