import { useState } from "react";
import { DiffEditor } from "@monaco-editor/react";
import type { GraphNode } from "../types";
import { STATUS_COLOR } from "../statusTheme";

function yamlList(title: string, items: string[]): string {
  if (!items.length) return `${title}: []`;
  return `${title}:\n${items.map((i) => `  - ${JSON.stringify(i)}`).join("\n")}`;
}

export default function DiffPane({
  node,
  staged,
}: {
  node: GraphNode | null;
  staged: string;
}) {
  const [tab, setTab] = useState<"diff" | "frame">("diff");
  if (!node) {
    return (
      <section className="flex h-full items-center justify-center bg-well text-[13px] text-ink-faint">
        Select a module in the graph to inspect its diff and attestation.
      </section>
    );
  }
  const color = STATUS_COLOR[node.status];
  const att = node.attestation;
  return (
    <section className="flex h-full min-w-0 flex-col bg-well">
      <div className="flex items-center gap-2 border-b border-line bg-pane px-3 py-1.5 text-[12px]">
        <span className="font-mono text-ink">{node.path}</span>
        <span style={{ color }}>●</span>
        <span className="text-ink-dim">{node.status}</span>
        <div className="ml-auto flex gap-1">
          {(["diff", "frame"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className="rounded px-2 py-0.5"
              style={
                tab === t
                  ? { background: "var(--color-pane2)", color: "var(--color-ink)" }
                  : { color: "var(--color-ink-dim)" }
              }
            >
              {t === "diff" ? "Diff" : "preserved_symbols & attestation"}
            </button>
          ))}
        </div>
      </div>
      {tab === "diff" ? (
        <div className="min-h-0 flex-1">
          <DiffEditor
            original={node.source}
            modified={staged || node.source}
            language="python"
            theme="vs-dark"
            options={{
              readOnly: false,
              renderSideBySide: true,
              minimap: { enabled: false },
              fontSize: 12.5,
              scrollBeyondLastLine: false,
            }}
          />
        </div>
      ) : (
        <div className="grid min-h-0 flex-1 grid-cols-2 gap-px overflow-auto bg-line">
          <pre className="m-0 overflow-auto bg-pane p-3 font-mono text-[12px] leading-5 text-ink">
            {`# ${node.node_id}.md frontmatter\n`}
            {yamlList("preserved_symbols", node.preserved_symbols)}
            {"\n"}
            {yamlList("invariants", node.invariants)}
            {"\n"}
            {yamlList("exports", node.exports)}
          </pre>
          <div className="overflow-auto bg-pane p-3 font-mono text-[12px] leading-5">
            <div className="mb-1 text-ink-dim"># latest SHA-256 attestation</div>
            {att ? (
              <>
                <div className="text-ink">payloadType: {att.payloadType}</div>
                <div className="text-ink">turn: {att.payload.turn}</div>
                <div className="break-all" style={{ color: "var(--color-verified)" }}>
                  sha256: {att.payload.sha256}
                </div>
                <div className="mt-1 text-ink-dim">
                  keyid: {att.signatures[0]?.keyid}
                </div>
                <div className="break-all text-ink-dim">
                  sig: {att.signatures[0]?.sig}
                </div>
              </>
            ) : (
              <div className="text-ink-faint">
                No attestation yet — this module has not passed Gate C.
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
