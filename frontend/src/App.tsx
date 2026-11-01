import { useCallback, useEffect, useRef, useState } from "react";
import StatusBar from "./components/StatusBar";
import GraphPane from "./components/GraphPane";
import DiffPane from "./components/DiffPane";
import GatePane from "./components/GatePane";
import { api, openSessionSocket } from "./api";
import {
  BILLING_STAGED,
  demoCost,
  demoEvents,
  demoGraph,
  demoTelemetry,
} from "./demo";
import type { CostPoint, GateEvent, Graph, Telemetry, WsMessage } from "./types";

const SESSION_KEY = "stepcheck.session";

export default function App() {
  const [live, setLive] = useState(false);
  const [graph, setGraph] = useState<Graph>(demoGraph);
  const [telemetry, setTelemetry] = useState<Telemetry>(demoTelemetry);
  const [events, setEvents] = useState<GateEvent[]>(demoEvents);
  const [cost, setCost] = useState<CostPoint[]>(demoCost);
  const [selected, setSelected] = useState<string | null>("billing");
  const [sessionId, setSessionId] = useState<string | null>(null);
  const turnRef = useRef(0);

  const onMessage = useCallback((m: WsMessage) => {
    setLive(true);
    if (m.type === "snapshot") {
      setGraph(m.graph);
      setTelemetry(m.telemetry);
      setEvents([]);
      setCost([{ turn: 0, raw: 0, compacted: 0 }]);
      turnRef.current = m.telemetry.turns;
      return;
    }
    if (m.type === "graph") setGraph(m.graph);
    if (m.type === "telemetry") {
      setTelemetry(m.telemetry);
      turnRef.current = m.telemetry.turns;
      setCost((c) => [
        ...c,
        {
          turn: m.telemetry.turns,
          raw: m.telemetry.raw_bloated_tokens,
          compacted: m.telemetry.compacted_okf_tokens,
        },
      ]);
    }
    if (m.type === "gate_event") {
      const { type: _type, ...ev } = m;
      setEvents((e) => [...e, { ...ev, turn: turnRef.current + 1 }]);
    }
  }, []);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const sid =
      params.get("session") ?? window.localStorage.getItem(SESSION_KEY);
    if (!sid) return; // no gateway session named — stay on the demo replay
    setSessionId(sid);
    window.localStorage.setItem(SESSION_KEY, sid);
    const close = openSessionSocket(sid, onMessage, () => setLive(false));
    return close;
  }, [onMessage]);

  const lock = useCallback(
    async (nodeId: string) => {
      if (!live || !sessionId) {
        // Demo replay: flip the status locally so the toggle is tangible.
        setGraph((g) => ({
          ...g,
          nodes: g.nodes.map((n) =>
            n.node_id === nodeId ? { ...n, locked: true, status: "LOCKED" } : n,
          ),
        }));
        return;
      }
      await api.lock(sessionId, nodeId);
    },
    [live, sessionId],
  );

  const sel = graph.nodes.find((n) => n.node_id === selected) ?? null;
  const staged = !live && selected === "billing" ? BILLING_STAGED : "";

  return (
    <div className="grid h-full grid-rows-[auto_1fr]">
      <StatusBar telemetry={telemetry} live={live} />
      <main className="grid min-h-0 grid-cols-[330px_minmax(0,1fr)_320px]">
        <GraphPane
          graph={graph}
          selected={selected}
          onSelect={setSelected}
          onLockToggle={lock}
        />
        <DiffPane node={sel} staged={staged} />
        <GatePane events={events} cost={cost} />
      </main>
    </div>
  );
}
