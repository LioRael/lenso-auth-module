import { configureConsoleBridge } from "@lenso/auth-console-ui-client";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "./styles.css";
import { AuthSessionsPage, AuthUsersPage } from "./page";

const surface = new URLSearchParams(window.location.search).get("surface") ?? "sessions";
configureConsoleBridge("lenso/auth", surface);

const root = document.getElementById("root");
if (!root) {
  throw new Error("Auth Console root is missing");
}

createRoot(root).render(
  <StrictMode>
    {surface === "users" ? <AuthUsersPage /> : <AuthSessionsPage />}
  </StrictMode>
);
