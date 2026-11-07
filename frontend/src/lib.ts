import type { AssessmentStatus, FindingRow, Severity } from "./types";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

export const MODULES: Record<string, { label: string; owasp: string; blurb: string }> = {
  prompt_injection: {
    label: "Prompt injection",
    owasp: "LLM01",
    blurb: "Can user text override the application's own rules?",
  },
  data_leakage: {
    label: "Data leakage",
    owasp: "LLM02 / LLM07",
    blurb: "Can secrets or the system prompt be made to surface?",
  },
  output: {
    label: "Output handling",
    owasp: "LLM05",
    blurb: "Does the model emit active content that an app might trust?",
  },
  tool_abuse: {
    label: "Agent and tools",
    owasp: "LLM06",
    blurb: "Can an injected instruction trigger a destructive tool call?",
  },
};

export const DEPTHS = [
  { id: "quick", label: "Quick", note: "1 replay per proof" },
  { id: "standard", label: "Standard", note: "3 replays per proof" },
  { id: "deep", label: "Deep", note: "5 replays per proof" },
] as const;

export interface Grade {
  label: string;
  tone: "bad" | "warn" | "fair" | "good";
}

/** Maps the 0-100 security score to a verdict. */
export function grade(score: number | null): Grade {
  if (score === null) return { label: "Not scored", tone: "fair" };
  if (score < 40) return { label: "Exposed", tone: "bad" };
  if (score < 70) return { label: "At risk", tone: "warn" };
  if (score < 90) return { label: "Holding", tone: "fair" };
  return { label: "Hardened", tone: "good" };
}

export function countBySeverity(rows: FindingRow[]): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const r of rows) if (r.status === "open") out[r.data.severity] += 1;
  return out;
}

export function sortFindings(rows: FindingRow[]): FindingRow[] {
  return [...rows].sort((a, b) => {
    if (a.status !== b.status) return a.status === "open" ? -1 : 1;
    return (b.data.risk_score ?? 0) - (a.data.risk_score ?? 0);
  });
}

/** Evidence strings quote the proof in single quotes, e.g. "Canary 'SECRET_TEST_4821' ...". */
export function extractProofTokens(evidence: string): string[] {
  const tokens: string[] = [];
  for (const m of evidence.matchAll(/'([^']{3,})'/g)) tokens.push(m[1]);
  return tokens;
}

export interface Segment {
  text: string;
  hit: boolean;
}

export function highlight(text: string, needles: string[]): Segment[] {
  const live = needles.filter(Boolean);
  if (live.length === 0) return [{ text, hit: false }];
  const escaped = live.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const re = new RegExp(`(${escaped.join("|")})`, "g");
  return text
    .split(re)
    .filter((s) => s !== "")
    .map((s) => ({ text: s, hit: live.includes(s) }));
}

export function formatDuration(seconds: number | null): string {
  if (seconds === null) return "-";
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`;
}

export function formatDate(iso: string | null): string {
  if (!iso) return "-";
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

export function statusTone(s: AssessmentStatus): "run" | "ok" | "bad" | "idle" {
  if (s === "running") return "run";
  if (s === "completed") return "ok";
  if (s === "failed") return "bad";
  if (s === "cancelled") return "idle";
  return "idle";
}

/** FastAPI returns either {detail: "text"} or {detail: [{loc, msg}, ...]} (validation). */
export function parseApiError(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "detail" in body) {
    const d = (body as { detail: unknown }).detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d)) {
      return d
        .map((e) => {
          const loc = Array.isArray(e?.loc) ? e.loc.filter((x: unknown) => x !== "body").join(".") : "";
          const msg = String(e?.msg ?? "invalid").replace(/^Value error, /, "");
          return loc ? `${loc}: ${msg}` : msg;
        })
        .join("; ");
    }
  }
  return fallback;
}

/** Module lanes: a lane is done once progress passed its share of the run. */
export function laneState(index: number, total: number, progress: number, status: AssessmentStatus) {
  if (status === "completed") return "done" as const;
  const done = Math.floor((progress / 100) * total);
  if (index < done) return "done" as const;
  if (index === done && status === "running") return "active" as const;
  return "queued" as const;
}
