import "@fontsource/ibm-plex-sans";
import "@fontsource/ibm-plex-mono";
import "@fontsource/source-serif-4";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./app";
import "./index.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
