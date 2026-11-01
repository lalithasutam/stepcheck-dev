import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import * as monaco from "monaco-editor";
import { loader } from "@monaco-editor/react";
import editorWorker from "monaco-editor/esm/vs/editor/editor.worker?worker";
import "./index.css";
import App from "./App";

// Bundle Monaco locally — the Studio must work with no CDN access.
self.MonacoEnvironment = { getWorker: () => new editorWorker() };
loader.config({ monaco });

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
