// Typed service layer for the DualDoorGateway (Seam 2). Components never fetch.
import type { Graph, Telemetry, WsMessage } from "./types";

export const API_BASE =
  (import.meta as { env?: Record<string, string> }).env?.VITE_API_BASE ??
  "http://127.0.0.1:8420";

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json() as Promise<T>;
}

export const api = {
  init: (projectRoot: string) =>
    post<{ session_id: string } & Graph>("/v1/step/init", {
      project_root: projectRoot,
    }),
  checkout: (sessionId: string, nodeId: string) =>
    post<{ rendered: string; token_count: number; frame_markdown: string }>(
      "/v1/step/checkout",
      { session_id: sessionId, node_id: nodeId },
    ),
  commit: (sessionId: string, nodeId: string, source: string) =>
    post("/v1/step/commit", {
      session_id: sessionId,
      node_id: nodeId,
      source,
    }),
  lock: (sessionId: string, nodeId: string) =>
    post<{ status: string }>("/v1/step/lock", {
      session_id: sessionId,
      node_id: nodeId,
    }),
  graph: async (sessionId: string): Promise<Graph> => {
    const res = await fetch(`${API_BASE}/v1/step/graph/${sessionId}`);
    return res.json() as Promise<Graph>;
  },
  telemetry: async (sessionId: string): Promise<Telemetry> => {
    const res = await fetch(`${API_BASE}/v1/step/telemetry/${sessionId}`);
    return res.json() as Promise<Telemetry>;
  },
};

export function openSessionSocket(
  sessionId: string,
  onMessage: (m: WsMessage) => void,
  onDown: () => void,
): () => void {
  const url = `${API_BASE.replace(/^http/, "ws")}/v1/ws/${sessionId}`;
  let ws: WebSocket | null = null;
  let closed = false;
  try {
    ws = new WebSocket(url);
    ws.onmessage = (ev) => onMessage(JSON.parse(ev.data) as WsMessage);
    ws.onerror = () => onDown();
    ws.onclose = () => {
      if (!closed) onDown();
    };
  } catch {
    onDown();
  }
  return () => {
    closed = true;
    ws?.close();
  };
}
