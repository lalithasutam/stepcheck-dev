import type { CostPoint, GateEvent } from "../types";
import CostChart from "./CostChart";

const GATE_NAME: Record<string, string> = {
  A: "Gate A · mechanical / locked",
  B: "Gate B · omission",
  C: "Gate C · logical invariant",
};

function EventRow({ ev }: { ev: GateEvent }) {
  const color = ev.accepted ? "var(--color-verified)" : "var(--color-rejected)";
  return (
    <li className="border-b border-line px-3 py-2 text-[12px] leading-5">
      <div className="flex items-center gap-2">
        <span style={{ color }}>{ev.accepted ? "✓" : "✕"}</span>
        <span className="font-mono text-ink">{ev.node_id}</span>
        <span className="text-ink-dim">
          {ev.accepted
            ? "passed A·B·C — attested"
            : GATE_NAME[ev.gate ?? ""] ?? "rejected"}
        </span>
        {typeof ev.turn === "number" && (
          <span className="ml-auto font-mono text-[10px] text-ink-faint">
            T{ev.turn}
          </span>
        )}
      </div>
      {!ev.accepted && ev.error && (
        <div className="mt-0.5 pl-5 text-ink-dim">
          {ev.subtype && (
            <span className="mr-1 font-mono text-[10px]" style={{ color: "var(--color-dirty)" }}>
              {ev.subtype}
            </span>
          )}
          {ev.error}
        </div>
      )}
      {ev.accepted && ev.dirtied.length > 0 && (
        <div className="mt-0.5 pl-5" style={{ color: "var(--color-dirty)" }}>
          export change → {ev.dirtied.join(", ")} now DIRTY_OMISSION_RISK
        </div>
      )}
    </li>
  );
}

export default function GatePane({
  events,
  cost,
}: {
  events: GateEvent[];
  cost: CostPoint[];
}) {
  return (
    <aside className="flex h-full flex-col border-l border-line bg-pane">
      <div className="border-b border-line px-3 py-2 text-[12px] text-ink-dim">
        3-tier gate feed
      </div>
      <ul className="m-0 min-h-0 flex-1 list-none overflow-auto p-0">
        {events.length === 0 ? (
          <li className="px-3 py-3 text-[12px] text-ink-faint">
            No commits yet this session.
          </li>
        ) : (
          [...events].reverse().map((ev, i) => <EventRow key={i} ev={ev} />)
        )}
      </ul>
      <div className="border-t border-line px-3 py-2">
        <div className="mb-1 text-[12px] text-ink-dim">
          Cumulative context cost (tokens)
        </div>
        <CostChart points={cost} />
      </div>
    </aside>
  );
}
