import { configureConsoleBridge } from "@lenso/auth-console-ui-client";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "./styles.css";
import { AuthDevicesPage } from "./page";

configureConsoleBridge("lenso/auth-device", "devices");

const root = document.getElementById("root");
if (!root) {
  throw new Error("Auth Device Console root is missing");
}

createRoot(root).render(
  <StrictMode>
    <AuthDevicesPage />
  </StrictMode>
);
