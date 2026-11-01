import type { CostPoint } from "../types";

const W = 290;
const H = 150;
const PAD = { l: 44, r: 8, t: 10, b: 20 };

function path(points: CostPoint[], key: "raw" | "compacted", max: number): string {
  if (points.length < 2) return "";
  const xs = (i: number) =>
    PAD.l + (i / (points.length - 1)) * (W - PAD.l - PAD.r);
  const ys = (v: number) => H - PAD.b - (v / max) * (H - PAD.t - PAD.b);
  return points
    .map((p, i) => `${i === 0 ? "M" : "L"}${xs(i).toFixed(1)},${ys(p[key]).toFixed(1)}`)
    .join(" ");
}

const kfmt = (v: number) => (v >= 1000 ? `${Math.round(v / 1000)}k` : `${v}`);

/** Cumulative context cost per turn: quadratic raw bloat vs StepCheck flat-line. */
export default function CostChart({ points }: { points: CostPoint[] }) {
  const max = Math.max(1, ...points.map((p) => p.raw));
  const ticks = [0, 0.5, 1].map((f) => Math.round(max * f));
  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      className="w-full"
      role="img"
      aria-label="Cumulative token cost: raw agent vs StepCheck"
    >
      {ticks.map((t) => {
        const y = H - PAD.b - (t / max) * (H - PAD.t - PAD.b);
        return (
          <g key={t}>
            <line x1={PAD.l} x2={W - PAD.r} y1={y} y2={y} stroke="var(--color-line)" strokeWidth="1" />
            <text x={PAD.l - 6} y={y + 3.5} textAnchor="end" fontSize="9" fill="var(--color-ink-faint)">
              {kfmt(t)}
            </text>
          </g>
        );
      })}
      <path d={path(points, "raw", max)} fill="none" stroke="var(--color-rejected)" strokeWidth="2" />
      <path d={path(points, "compacted", max)} fill="none" stroke="var(--color-verified)" strokeWidth="2" />
      <text x={PAD.l} y={H - 6} fontSize="9" fill="var(--color-rejected)">
        raw bloat (quadratic)
      </text>
      <text x={W - PAD.r} y={H - 6} fontSize="9" textAnchor="end" fill="var(--color-verified)">
        StepCheck (flat)
      </text>
    </svg>
  );
}
