export type NodeStatus =
  | "ACTIVE"
  | "VERIFIED"
  | "LOCKED"
  | "DIRTY_OMISSION_RISK"
  | "REJECTED";

export interface Attestation {
  payloadType: string;
  payload: {
    node_id: string;
    path: string;
    sha256: string;
    exports: string[];
    turn: number;
  };
  signatures: { keyid: string; sig: string }[];
}

export interface GraphNode {
  node_id: string;
  path: string;
  status: NodeStatus;
  locked: boolean;
  deps: string[];
  exports: string[];
  preserved_symbols: string[];
  invariants: string[];
  verified: number;
  attestation: Attestation | null;
  source: string;
}

export interface Graph {
  nodes: GraphNode[];
  edges: { source: string; target: string }[];
}

export interface Telemetry {
  raw_bloated_tokens: number;
  compacted_okf_tokens: number;
  tokens_saved: number;
  dollars_saved: number;
  omissions_blocked: number;
  turns: number;
}

export interface GateEvent {
  node_id: string;
  accepted: boolean;
  gate: "A" | "B" | "C" | null;
  error: string | null;
  subtype: string | null;
  dirtied: string[];
  turn?: number;
}

export type WsMessage =
  | { type: "snapshot"; graph: Graph; telemetry: Telemetry }
  | { type: "graph"; graph: Graph }
  | { type: "telemetry"; telemetry: Telemetry }
  | ({ type: "gate_event" } & GateEvent);

export interface CostPoint {
  turn: number;
  raw: number;
  compacted: number;
}
