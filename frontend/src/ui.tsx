import type { ReactNode } from "react";
import { grade } from "./lib";
import type { Severity } from "./types";
import { SEVERITIES } from "./lib";

const ICONS: Record<string, string> = {
  shield: "M12 2.5 20 6v6c0 4.6-3.2 8-8 9.5C7.2 20 4 16.6 4 12V6z",
  grid: "M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z",
  plus: "M12 5v14M5 12h14",
  target: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8z",
  file: "M7 3h7l5 5v13H7zM14 3v5h5",
  refresh: "M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7",
  close: "M6 6l12 12M18 6 6 18",
  out: "M10 4H5v16h5M15 8l4 4-4 4M19 12H9",
  check: "M5 12.5l4.5 4.5L19 7",
  alert: "M12 4 2.5 20h19zM12 10v4.5M12 17.5v.01",
  arrow: "M5 12h14M13 6l6 6-6 6",
};

export function Icon({ name, size = 16 }: { name: keyof typeof ICONS; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={ICONS[name]} />
    </svg>
  );
}

export function Chip({ tone, children }: { tone: string; children: ReactNode }) {
  return <span className={`chip chip-${tone}`}>{children}</span>;
}

export function SevDot({ sev }: { sev: Severity }) {
  return <span className={`sevdot sev-${sev}`} title={sev} />;
}

/** Half-circle gauge: arc fills with the score, ticks every 10 points. */
export function Gauge({ score, size = 220 }: { score: number | null; size?: number }) {
  const r = 80;
  const len = Math.PI * r;
  const pct = score === null ? 0 : Math.max(0, Math.min(100, score));
  const g = grade(score);
  const ticks = Array.from({ length: 11 }, (_, i) => {
    const a = Math.PI - (i / 10) * Math.PI;
    return {
      x1: 100 + Math.cos(a) * (r + 10),
      y1: 100 - Math.sin(a) * (r + 10),
      x2: 100 + Math.cos(a) * (r + (i % 5 === 0 ? 17 : 14)),
      y2: 100 - Math.sin(a) * (r + (i % 5 === 0 ? 17 : 14)),
    };
  });
  return (
    <figure className={`gauge tone-${g.tone}`} style={{ width: size }}>
      <svg viewBox="0 0 200 128" role="img" aria-label={`Security score ${score ?? "n/a"} out of 100`}>
        {ticks.map((t, i) => (
          <line key={i} {...t} className="gauge-tick" />
        ))}
        <path d="M20 100A80 80 0 0 1 180 100" className="gauge-track" />
        <path
          d="M20 100A80 80 0 0 1 180 100"
          className="gauge-fill"
          strokeDasharray={`${(len * pct) / 100} ${len}`}
        />
      </svg>
      <figcaption>
        <strong>{score ?? "-"}</strong>
        <span>{g.label}</span>
      </figcaption>
    </figure>
  );
}

export function Sparkline({ values, width = 120, height = 32 }: { values: number[]; width?: number; height?: number }) {
  if (values.length < 2) {
    return <span className="spark-empty">{values.length === 1 ? "1 scan" : "no scans"}</span>;
  }
  const step = width / (values.length - 1);
  const pts = values.map((v, i) => [i * step, height - 3 - (Math.max(0, Math.min(100, v)) / 100) * (height - 6)]);
  const d = pts.map((p, i) => `${i ? "L" : "M"}${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(" ");
  const last = pts[pts.length - 1];
  return (
    <svg width={width} height={height} className="spark" aria-hidden="true">
      <path d={d} />
      <circle cx={last[0]} cy={last[1]} r="2.6" />
    </svg>
  );
}

/** Four stacked rows, one per severity, scaled to the largest count. */
export function SeverityBars({ counts }: { counts: Record<Severity, number> }) {
  const max = Math.max(1, ...SEVERITIES.map((s) => counts[s]));
  return (
    <ul className="sevbars">
      {SEVERITIES.map((s) => (
        <li key={s}>
          <span className="sevbars-label">{s}</span>
          <span className="sevbars-track">
            <span className={`sev-${s}`} style={{ width: `${(counts[s] / max) * 100}%` }} />
          </span>
          <span className="sevbars-n">{counts[s]}</span>
        </li>
      ))}
    </ul>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <h3>{title}</h3>
      {children && <p>{children}</p>}
    </div>
  );
}

export function ErrorNote({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="note note-bad" role="alert">
      <Icon name="alert" />
      <span>{message}</span>
      {onRetry && (
        <button className="btn btn-ghost" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}
