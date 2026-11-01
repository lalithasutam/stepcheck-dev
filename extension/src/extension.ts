// StepCheck Studio webview wrapper. Command contributions follow the
// vscode-ext-commands conventions: `<extension>.<verb><Noun>` ids, a shared
// "StepCheck" category, Title Case titles, enablement over runtime no-ops.
import * as vscode from "vscode";

let panel: vscode.WebviewPanel | undefined;

function studioHtml(studioUrl: string, gatewayUrl: string): string {
  const url = `${studioUrl.replace(/\/$/, "")}/?gateway=${encodeURIComponent(gatewayUrl)}`;
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; frame-src ${studioUrl} http: https:; style-src 'unsafe-inline';" />
  <style>
    html, body { height: 100%; margin: 0; background: #0e1116; }
    iframe { width: 100%; height: 100%; border: 0; }
    .hint { color: #8a96a5; font: 12px system-ui; padding: 12px; }
  </style>
</head>
<body>
  <iframe src="${url}" title="StepCheck Studio"
          sandbox="allow-scripts allow-same-origin allow-forms"></iframe>
  <noscript><div class="hint">Enable scripts to load StepCheck Studio.</div></noscript>
</body>
</html>`;
}

function openStudio(column: vscode.ViewColumn): void {
  const config = vscode.workspace.getConfiguration("stepcheck");
  const studioUrl = config.get<string>("studioUrl", "http://127.0.0.1:5173");
  const gatewayUrl = config.get<string>("gatewayUrl", "http://127.0.0.1:8420");

  if (panel) {
    panel.reveal(column);
    return;
  }
  panel = vscode.window.createWebviewPanel(
    "stepcheck.studio",
    "StepCheck Studio",
    column,
    { enableScripts: true, retainContextWhenHidden: true },
  );
  panel.webview.html = studioHtml(studioUrl, gatewayUrl);
  void vscode.commands.executeCommand("setContext", "stepcheck.studioOpen", true);
  panel.onDidDispose(() => {
    panel = undefined;
    void vscode.commands.executeCommand(
      "setContext",
      "stepcheck.studioOpen",
      false,
    );
  });
}

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("stepcheck.openStudio", () =>
      openStudio(vscode.ViewColumn.Active),
    ),
    vscode.commands.registerCommand("stepcheck.openStudioToSide", () =>
      openStudio(vscode.ViewColumn.Beside),
    ),
  );
}

export function deactivate(): void {
  panel?.dispose();
}
