import { useMemo } from "react";
import {
  Background,
  Handle,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { Graph, GraphNode } from "../types";
import { STATUS_COLOR, STATUS_LABEL } from "../statusTheme";

type OkfFlowNode = Node<{ okf: GraphNode; selected: boolean }, "okf">;

function OkfNode({ data }: NodeProps<OkfFlowNode>) {
  const { okf, selected } = data;
  const color = STATUS_COLOR[okf.status];
  return (
    <div
      className="min-w-36 rounded border bg-pane2 px-3 py-2 text-left"
      style={{
        borderColor: color,
        boxShadow: selected ? `0 0 0 2px ${color}` : undefined,
      }}
    >
      <Handle type="target" position={Position.Top} style={{ opacity: 0 }} />
      <div className="flex items-center gap-1.5 font-mono text-[13px] text-ink">
        {okf.locked ? "🔒 " : ""}
        {okf.node_id}
        {okf.verified > 0 && (
          <span title={`${okf.verified} attestation(s)`} className="text-[10px]" style={{ color }}>
            ✓{okf.verified}
          </span>
        )}
      </div>
      <div className="mt-0.5 text-[10px]" style={{ color }}>
        {STATUS_LABEL[okf.status]}
      </div>
      <Handle type="source" position={Position.Bottom} style={{ opacity: 0 }} />
    </div>
  );
}

const nodeTypes = { okf: OkfNode };

/** Layered layout: depth = longest path to a leaf dependency. */
function layout(graph: Graph): { nodes: OkfFlowNode[]; edges: Edge[] } {
  const depth = new Map<string, number>();
  const byId = new Map(graph.nodes.map((n) => [n.node_id, n]));
  const d = (id: string, seen: Set<string>): number => {
    if (depth.has(id)) return depth.get(id)!;
    if (seen.has(id)) return 0;
    seen.add(id);
    const node = byId.get(id);
    const v = node && node.deps.length
      ? 1 + Math.max(...node.deps.map((x) => d(x, seen)))
      : 0;
    depth.set(id, v);
    return v;
  };
  graph.nodes.forEach((n) => d(n.node_id, new Set()));
  const rows = new Map<number, string[]>();
  for (const n of graph.nodes) {
    const row = depth.get(n.node_id) ?? 0;
    rows.set(row, [...(rows.get(row) ?? []), n.node_id]);
  }
  const maxRow = Math.max(...rows.keys(), 0);
  const pos = new Map<string, { x: number; y: number }>();
  for (const [row, ids] of rows) {
    ids.sort();
    ids.forEach((id, i) => {
      pos.set(id, { x: 30 + i * 185, y: 40 + (maxRow - row) * 120 });
    });
  }
  return {
    nodes: graph.nodes.map((n) => ({
      id: n.node_id,
      type: "okf",
      position: pos.get(n.node_id) ?? { x: 0, y: 0 },
      data: { okf: n, selected: false },
    })),
    edges: graph.edges.map((e) => ({
      id: `${e.source}->${e.target}`,
      source: e.source,
      target: e.target,
      animated: byId.get(e.source)?.status === "DIRTY_OMISSION_RISK",
      style: { stroke: "var(--color-line)", strokeWidth: 1.5 },
    })),
  };
}

export default function GraphPane({
  graph,
  selected,
  onSelect,
  onLockToggle,
}: {
  graph: Graph;
  selected: string | null;
  onSelect: (id: string) => void;
  onLockToggle: (id: string) => void;
}) {
  const { nodes, edges } = useMemo(() => layout(graph), [graph]);
  const decorated = useMemo(
    () =>
      nodes.map((n) => ({
        ...n,
        data: { ...n.data, selected: n.id === selected },
      })),
    [nodes, selected],
  );
  const sel = graph.nodes.find((n) => n.node_id === selected) ?? null;

  return (
    <section className="flex h-full flex-col border-r border-line bg-pane">
      <div className="border-b border-line px-3 py-2 text-[12px] text-ink-dim">
        OKF dependency graph — {graph.nodes.length} modules
      </div>
      <div className="min-h-0 flex-1">
        <ReactFlow
          nodes={decorated}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodeClick={(_, n) => onSelect(n.id)}
          fitView
          proOptions={{ hideAttribution: false }}
          nodesDraggable
          nodesConnectable={false}
          colorMode="dark"
          style={{ background: "var(--color-well)" }}
        >
          <Background color="#1c232d" gap={18} />
        </ReactFlow>
      </div>
      <div className="border-t border-line px-3 py-2.5">
        {sel ? (
          <button
            className="w-full rounded border px-2 py-1.5 font-mono text-[12px] text-ink hover:bg-pane2 disabled:opacity-40"
            style={{ borderColor: STATUS_COLOR[sel.status] }}
            disabled={sel.locked}
            onClick={() => onLockToggle(sel.node_id)}
          >
            {sel.locked ? `🔒 ${sel.node_id} is locked` : `Pin & Lock ${sel.node_id}`}
          </button>
        ) : (
          <div className="text-[12px] text-ink-faint">
            Select a module to pin &amp; lock its invariants.
          </div>
        )}
      </div>
    </section>
  );
}
