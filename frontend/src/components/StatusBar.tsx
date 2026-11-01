import type { Telemetry } from "../types";

function pct(t: Telemetry): number {
  if (!t.raw_bloated_tokens) return 0;
  return Math.round((t.tokens_saved / t.raw_bloated_tokens) * 100);
}

const fmt = new Intl.NumberFormat("en-US");

export default function StatusBar({
  telemetry,
  live,
}: {
  telemetry: Telemetry;
  live: boolean;
}) {
  return (
    <header className="flex h-11 items-center gap-5 border-b border-line bg-pane px-4 text-[13px]">
      <span className="font-semibold tracking-tight text-ink">
        ⚡ StepCheck Studio
      </span>
      <span
        className="rounded-sm px-1.5 py-0.5 text-[11px]"
        style={{
          color: live ? "var(--color-verified)" : "var(--color-dirty)",
          background: live ? "#3fb87f1a" : "#e0a33b1a",
        }}
        title={live ? "Streaming from the gateway" : "Gateway unreachable — replaying a built-in session"}
      >
        {live ? "live" : "demo replay"}
      </span>
      <span className="text-ink-dim">
        Turn <span className="font-mono text-ink">{telemetry.turns}</span>
      </span>
      <span className="text-ink-dim">
        Raw{" "}
        <span className="font-mono text-ink">
          {fmt.format(telemetry.raw_bloated_tokens)}
        </span>{" "}
        → Compacted{" "}
        <span className="font-mono text-ink">
          {fmt.format(telemetry.compacted_okf_tokens)}
        </span>{" "}
        tokens{" "}
        <span className="font-mono" style={{ color: "var(--color-verified)" }}>
          ({pct(telemetry)}% saved)
        </span>
      </span>
      <span
        className="ml-auto font-mono text-[15px] font-semibold tabular-nums"
        style={{ color: "var(--color-verified)" }}
      >
        ${telemetry.dollars_saved.toFixed(4)} saved
      </span>
      <span className="text-ink-dim">
        Omissions caught{" "}
        <span
          className="font-mono font-semibold"
          style={{ color: "var(--color-dirty)" }}
        >
          {telemetry.omissions_blocked}
        </span>
      </span>
    </header>
  );
}
