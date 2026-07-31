import { configureConsoleBridge } from "@lenso/auth-console-ui-client";
import { StrictMode, type ReactNode } from "react";
import { createRoot } from "react-dom/client";

import "./styles.css";
import {
  AuthProvidersPage,
  GitHubProviderPage,
  GoogleProviderPage,
  OidcProviderPage,
} from "./page";

const surface = new URLSearchParams(window.location.search).get("surface") ?? "providers";
configureConsoleBridge(providerModule(surface), bridgeSurface(surface));

const root = document.getElementById("root");
if (!root) {
  throw new Error("Auth Provider Console root is missing");
}

createRoot(root).render(<StrictMode>{page(surface)}</StrictMode>);

function page(value: string): ReactNode {
  switch (value) {
    case "github":
      return <GitHubProviderPage />;
    case "google":
      return <GoogleProviderPage />;
    case "oidc":
      return <OidcProviderPage />;
    default:
      return <AuthProvidersPage />;
  }
}

function providerModule(value: string): string {
  return value === "github" ? "auth-github" : value === "google" ? "auth-google" : "auth-oidc";
}

function bridgeSurface(value: string): string {
  return value === "providers" ? value : `${value}-provider`;
}
